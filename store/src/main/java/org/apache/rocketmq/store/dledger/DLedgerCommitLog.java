/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.rocketmq.store.dledger;

import io.openmessaging.storage.dledger.AppendFuture;
import io.openmessaging.storage.dledger.BatchAppendFuture;
import io.openmessaging.storage.dledger.DLedgerConfig;
import io.openmessaging.storage.dledger.DLedgerServer;
import io.openmessaging.storage.dledger.entry.DLedgerEntry;
import io.openmessaging.storage.dledger.protocol.AppendEntryRequest;
import io.openmessaging.storage.dledger.protocol.AppendEntryResponse;
import io.openmessaging.storage.dledger.protocol.BatchAppendEntryRequest;
import io.openmessaging.storage.dledger.protocol.DLedgerResponseCode;
import io.openmessaging.storage.dledger.store.file.DLedgerMmapFileStore;
import io.openmessaging.storage.dledger.store.file.MmapFile;
import io.openmessaging.storage.dledger.store.file.MmapFileList;
import io.openmessaging.storage.dledger.store.file.SelectMmapBufferResult;
import io.openmessaging.storage.dledger.utils.DLedgerUtils;
import java.net.Inet6Address;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import org.apache.rocketmq.common.UtilAll;
import org.apache.rocketmq.common.message.MessageAccessor;
import org.apache.rocketmq.common.message.MessageConst;
import org.apache.rocketmq.common.message.MessageDecoder;
import org.apache.rocketmq.common.message.MessageExtBatch;
import org.apache.rocketmq.common.sysflag.MessageSysFlag;
import org.apache.rocketmq.common.topic.TopicValidator;
import org.apache.rocketmq.store.AppendMessageResult;
import org.apache.rocketmq.store.AppendMessageStatus;
import org.apache.rocketmq.store.CommitLog;
import org.apache.rocketmq.store.DefaultMessageStore;
import org.apache.rocketmq.store.DispatchRequest;
import org.apache.rocketmq.store.MappedFile;
import org.apache.rocketmq.store.MessageExtBrokerInner;
import org.apache.rocketmq.store.PutMessageResult;
import org.apache.rocketmq.store.PutMessageStatus;
import org.apache.rocketmq.store.SelectMappedBufferResult;
import org.apache.rocketmq.store.StoreStatsService;
import org.apache.rocketmq.store.schedule.ScheduleMessageService;

/**
 * Store all metadata downtime for recovery, data protection reliability
 * Dledger实现的CommitLog
 */
public class DLedgerCommitLog extends CommitLog {
    //基于Raft 协议实现的集群内的一个节点，用DLedgerServer 实例表示
    private final DLedgerServer dLedgerServer;
    //DLedger 的配置信息
    private final DLedgerConfig dLedgerConfig;
    //DLedger 基于文件映射的存储实现
    private final DLedgerMmapFileStore dLedgerFileStore;
    //DLedger 所管理的存储文件集合，对比RocketMQ中的MappedFileQueue
    private final MmapFileList dLedgerFileList;
    //The id identifies the broker role, 0 means master, others means slave 节点ID，0 表示主节点，非0 表示从节点
    private final int id;
    //消息序列器
    private final MessageSerializer messageSerializer;
    //用于记录消息追加的时耗(日志追加所持有锁时间)
    private volatile long beginTimeInDledgerLock = 0;
    //This offset separate the old commitlog from dledger commitlog
    //记录的旧Commitlog文件中的最大偏移量，如果访问的偏移量大于它，则访问Dledger 管理的文件
    private long dividedCommitlogOffset = -1;
    //是否正在恢复旧的Commitlog文件
    private boolean isInrecoveringOldCommitlog = false;

    private final StringBuilder msgIdBuilder = new StringBuilder();

    public DLedgerCommitLog(final DefaultMessageStore defaultMessageStore) {
        super(defaultMessageStore);
        dLedgerConfig = new DLedgerConfig();
        //是否强制删除文件，取自Broker配置属性cleanFileForciblyEnable，默认为true
        dLedgerConfig.setEnableDiskForceClean(defaultMessageStore.getMessageStoreConfig().isCleanFileForciblyEnable());
        //DLedger存储类型，固定为基于文件的存储模式
        dLedgerConfig.setStoreType(DLedgerConfig.FILE);
        //Leader节点的id 名称，示例配置：n0，其配置要求第二个字符后必须是数字。
        dLedgerConfig.setSelfId(defaultMessageStore.getMessageStoreConfig().getdLegerSelfId());
        //DLeger group 的名称，建议与broker 配置属性brokerName 保持一致
        dLedgerConfig.setGroup(defaultMessageStore.getMessageStoreConfig().getdLegerGroup());
        //DLeger Group 中所有的节点信息，其配置示例n0-127.0.0.1:40911;n1-127.0.0.1:40912;n2-127.0.0.1:40913。多个节点使用分号隔开。
        dLedgerConfig.setPeers(defaultMessageStore.getMessageStoreConfig().getdLegerPeers());
        //设置DLedger 的日志文件的根目录，取自borker 配件文件中的storePathRootDir ，即RocketMQ 的数据存储根路径。
        dLedgerConfig.setStoreBaseDir(defaultMessageStore.getMessageStoreConfig().getStorePathRootDir());
        //设置DLedger 的单个日志文件的大小，取自Broker 配置文件中的mapedFileSizeCommitLog，即与Commitlog 文件的单个文件大小一致
        dLedgerConfig.setMappedFileSizeForEntryData(defaultMessageStore.getMessageStoreConfig().getMappedFileSizeCommitLog());
        //DLedger 日志文件的删除时间，取自Broker 配置文件中的deleteWhen，默认为凌晨4 点
        dLedgerConfig.setDeleteWhen(defaultMessageStore.getMessageStoreConfig().getDeleteWhen());
        //DLedger 日志文件保留时长，取自Broker 配置文件中的fileReservedHours，默认为72h
        dLedgerConfig.setFileReservedHours(defaultMessageStore.getMessageStoreConfig().getFileReservedTime() + 1);
        dLedgerConfig.setPreferredLeaderId(defaultMessageStore.getMessageStoreConfig().getPreferredLeaderId());
        dLedgerConfig.setEnableBatchPush(defaultMessageStore.getMessageStoreConfig().isEnableBatchPush());

        id = Integer.valueOf(dLedgerConfig.getSelfId().substring(1)) + 1;
        //根据DLedger 配置信息创建DLedgerServer，即创建DLedger 集群节点，集群内各个节点启动后，就会触发选主
        dLedgerServer = new DLedgerServer(dLedgerConfig);
        dLedgerFileStore = (DLedgerMmapFileStore) dLedgerServer.getdLedgerStore();
        DLedgerMmapFileStore.AppendHook appendHook = (entry, buffer, bodyOffset) -> {
            assert bodyOffset == DLedgerEntry.BODY_OFFSET;
            buffer.position(buffer.position() + bodyOffset + MessageDecoder.PHY_POS_POSITION);
            buffer.putLong(entry.getPos() + bodyOffset);
        };
        dLedgerFileStore.addAppendHook(appendHook);
        dLedgerFileList = dLedgerFileStore.getDataFileList();
        //构建消息序列化
        this.messageSerializer = new MessageSerializer(defaultMessageStore.getMessageStoreConfig().getMaxMessageSize());
    }

    @Override
    public boolean load() {
        return super.load();
    }

    private void refreshConfig() {
        dLedgerConfig.setEnableDiskForceClean(defaultMessageStore.getMessageStoreConfig().isCleanFileForciblyEnable());
        dLedgerConfig.setDeleteWhen(defaultMessageStore.getMessageStoreConfig().getDeleteWhen());
        dLedgerConfig.setFileReservedHours(defaultMessageStore.getMessageStoreConfig().getFileReservedTime() + 1);
    }

    private void disableDeleteDledger() {
        dLedgerConfig.setEnableDiskForceClean(false);
        dLedgerConfig.setFileReservedHours(24 * 365 * 10);
    }

    @Override
    public void start() {
        dLedgerServer.startup();
    }

    @Override
    public void shutdown() {
        dLedgerServer.shutdown();
    }

    @Override
    public long flush() {
        dLedgerFileStore.flush();
        return dLedgerFileList.getFlushedWhere();
    }

    @Override
    public long getMaxOffset() {
        if (dLedgerFileStore.getCommittedPos() > 0) {
            return dLedgerFileStore.getCommittedPos();
        }
        if (dLedgerFileList.getMinOffset() > 0) {
            return dLedgerFileList.getMinOffset();
        }
        return 0;
    }

    @Override
    public long getMinOffset() {
        if (!mappedFileQueue.getMappedFiles().isEmpty()) {
            return mappedFileQueue.getMinOffset();
        }
        return dLedgerFileList.getMinOffset();
    }

    @Override
    public long getConfirmOffset() {
        return this.getMaxOffset();
    }

    @Override
    public void setConfirmOffset(long phyOffset) {
        log.warn("Should not set confirm offset {} for dleger commitlog", phyOffset);
    }

    @Override
    public long remainHowManyDataToCommit() {
        return dLedgerFileList.remainHowManyDataToCommit();
    }

    @Override
    public long remainHowManyDataToFlush() {
        return dLedgerFileList.remainHowManyDataToFlush();
    }

    @Override
    public int deleteExpiredFile(
        final long expiredTime,
        final int deleteFilesInterval,
        final long intervalForcibly,
        final boolean cleanImmediately
    ) {
        if (mappedFileQueue.getMappedFiles().isEmpty()) {
            refreshConfig();
            //To prevent too much log in defaultMessageStore
            return Integer.MAX_VALUE;
        } else {
            disableDeleteDledger();
        }
        int count = super.deleteExpiredFile(expiredTime, deleteFilesInterval, intervalForcibly, cleanImmediately);
        if (count > 0 || mappedFileQueue.getMappedFiles().size() != 1) {
            return count;
        }
        //the old logic will keep the last file, here to delete it
        MappedFile mappedFile = mappedFileQueue.getLastMappedFile();
        log.info("Try to delete the last old commitlog file {}", mappedFile.getFileName());
        long liveMaxTimestamp = mappedFile.getLastModifiedTimestamp() + expiredTime;
        if (System.currentTimeMillis() >= liveMaxTimestamp || cleanImmediately) {
            while (!mappedFile.destroy(10 * 1000)) {
                DLedgerUtils.sleep(1000);
            }
            mappedFileQueue.getMappedFiles().remove(mappedFile);
        }
        return 1;
    }

    public SelectMappedBufferResult convertSbr(SelectMmapBufferResult sbr) {
        if (sbr == null) {
            return null;
        } else {
            return new DLedgerSelectMappedBufferResult(sbr);
        }

    }

    public SelectMmapBufferResult truncate(SelectMmapBufferResult sbr) {
        long committedPos = dLedgerFileStore.getCommittedPos();
        if (sbr == null || sbr.getStartOffset() == committedPos) {
            return null;
        }
        if (sbr.getStartOffset() + sbr.getSize() <= committedPos) {
            return sbr;
        } else {
            sbr.setSize((int) (committedPos - sbr.getStartOffset()));
            return sbr;
        }
    }

    @Override
    public SelectMappedBufferResult getData(final long offset) {
        if (offset < dividedCommitlogOffset) {
            return super.getData(offset);
        }
        return this.getData(offset, offset == 0);
    }

    @Override
    public SelectMappedBufferResult getData(final long offset, final boolean returnFirstOnNotFound) {
        if (offset < dividedCommitlogOffset) {
            return super.getData(offset, returnFirstOnNotFound);
        }
        if (offset >= dLedgerFileStore.getCommittedPos()) {
            return null;
        }
        int mappedFileSize = this.dLedgerServer.getdLedgerConfig().getMappedFileSizeForEntryData();
        MmapFile mappedFile = this.dLedgerFileList.findMappedFileByOffset(offset, returnFirstOnNotFound);
        if (mappedFile != null) {
            int pos = (int) (offset % mappedFileSize);
            SelectMmapBufferResult sbr = mappedFile.selectMappedBuffer(pos);
            return convertSbr(truncate(sbr));
        }

        return null;
    }

    /**
     * 恢复
     * @param maxPhyOffsetOfConsumeQueue 消息消费队列最大物理偏移量
     */
    private void recover(long maxPhyOffsetOfConsumeQueue) {
        dLedgerFileStore.load();
        if (dLedgerFileList.getMappedFiles().size() > 0) {
            dLedgerFileStore.recover();
            //DLedger中所有物理文件的最小偏移量,操作消息的物理偏移量小于该值，则从Commitlog文件中查找；物理偏移量大于等于该值的话则从DLedger相关的文件中查找消息
            dividedCommitlogOffset = dLedgerFileList.getFirstMappedFile().getFileFromOffset();
            MappedFile mappedFile = this.mappedFileQueue.getLastMappedFile();
            //如果存在旧的Commitlog 文件，则禁止删除DLedger文件，其具体做法就是禁止强制删除文件，并将文件的有效存储时间设置为10年
            if (mappedFile != null) {
                //目的是防止CommitLog的偏移量与Dledger文件的偏移量出现断层
                disableDeleteDledger();
            }
            //Dledger最大物理偏移量
            long maxPhyOffset = dLedgerFileList.getMaxWrotePosition();
            // Clear ConsumeQueue redundant data
            if (maxPhyOffsetOfConsumeQueue >= maxPhyOffset) {
                //Consumequeue中存储的最大物理偏移量大于DLedger中最大的物理偏移量，则删除多余的Consumequeue文件
                log.warn("[TruncateCQ]maxPhyOffsetOfConsumeQueue({}) >= processOffset({}), truncate dirty logic files", maxPhyOffsetOfConsumeQueue, maxPhyOffset);
                this.defaultMessageStore.truncateDirtyLogicFiles(maxPhyOffset);
            }
            return;
        }
        //Indicate that, it is the first time to load mixed commitlog, need to recover the old commitlog
        isInrecoveringOldCommitlog = true;
        //No need the abnormal recover 正常恢复
        super.recoverNormally(maxPhyOffsetOfConsumeQueue);
        isInrecoveringOldCommitlog = false;
        MappedFile mappedFile = this.mappedFileQueue.getLastMappedFile();
        if (mappedFile == null) {
            return;
        }
        ByteBuffer byteBuffer = mappedFile.sliceByteBuffer();
        byteBuffer.position(mappedFile.getWrotePosition());
        boolean needWriteMagicCode = true;
        // 1 TOTAL SIZE
        byteBuffer.getInt(); //size
        int magicCode = byteBuffer.getInt();
        if (magicCode == CommitLog.BLANK_MAGIC_CODE) {
            needWriteMagicCode = false;
        } else {
            log.info("Recover old commitlog found a illegal magic code={}", magicCode);
        }
        dLedgerConfig.setEnableDiskForceClean(false);
        dividedCommitlogOffset = mappedFile.getFileFromOffset() + mappedFile.getFileSize();
        log.info("Recover old commitlog needWriteMagicCode={} pos={} file={} dividedCommitlogOffset={}", needWriteMagicCode, mappedFile.getFileFromOffset() + mappedFile.getWrotePosition(), mappedFile.getFileName(), dividedCommitlogOffset);
        if (needWriteMagicCode) {
            byteBuffer.position(mappedFile.getWrotePosition());
            byteBuffer.putInt(mappedFile.getFileSize() - mappedFile.getWrotePosition());
            byteBuffer.putInt(BLANK_MAGIC_CODE);
            mappedFile.flush(0);
        }
        mappedFile.setWrotePosition(mappedFile.getFileSize());
        mappedFile.setCommittedPosition(mappedFile.getFileSize());
        mappedFile.setFlushedPosition(mappedFile.getFileSize());
        dLedgerFileList.getLastMappedFile(dividedCommitlogOffset);
        log.info("Will set the initial commitlog offset={} for dledger", dividedCommitlogOffset);
    }

    /**
     * 正常恢复
     * @param maxPhyOffsetOfConsumeQueue 消息消费队列最大物理偏移量
     */
    @Override
    public void recoverNormally(long maxPhyOffsetOfConsumeQueue) {
        recover(maxPhyOffsetOfConsumeQueue);
    }

    @Override
    public void recoverAbnormally(long maxPhyOffsetOfConsumeQueue) {
        recover(maxPhyOffsetOfConsumeQueue);
    }

    @Override
    public DispatchRequest checkMessageAndReturnSize(ByteBuffer byteBuffer, final boolean checkCRC) {
        return this.checkMessageAndReturnSize(byteBuffer, checkCRC, true);
    }

    @Override
    public DispatchRequest checkMessageAndReturnSize(ByteBuffer byteBuffer, final boolean checkCRC,
        final boolean readBody) {
        if (isInrecoveringOldCommitlog) {
            return super.checkMessageAndReturnSize(byteBuffer, checkCRC, readBody);
        }
        try {
            int bodyOffset = DLedgerEntry.BODY_OFFSET;
            int pos = byteBuffer.position();
            int magic = byteBuffer.getInt();
            //In dledger, this field is size, it must be gt 0, so it could prevent collision
            int magicOld = byteBuffer.getInt();
            if (magicOld == CommitLog.BLANK_MAGIC_CODE || magicOld == CommitLog.MESSAGE_MAGIC_CODE) {
                byteBuffer.position(pos);
                return super.checkMessageAndReturnSize(byteBuffer, checkCRC, readBody);
            }
            if (magic == MmapFileList.BLANK_MAGIC_CODE) {
                return new DispatchRequest(0, true);
            }
            byteBuffer.position(pos + bodyOffset);
            DispatchRequest dispatchRequest = super.checkMessageAndReturnSize(byteBuffer, checkCRC, readBody);
            if (dispatchRequest.isSuccess()) {
                dispatchRequest.setBufferSize(dispatchRequest.getMsgSize() + bodyOffset);
            } else if (dispatchRequest.getMsgSize() > 0) {
                dispatchRequest.setBufferSize(dispatchRequest.getMsgSize() + bodyOffset);
            }
            return dispatchRequest;
        } catch (Throwable ignored) {
        }

        return new DispatchRequest(-1, false /* success */);
    }

    @Override
    public boolean resetOffset(long offset) {
        //currently, it seems resetOffset has no use
        return false;
    }

    @Override
    public long getBeginTimeInLock() {
        return beginTimeInDledgerLock;
    }

    private void setMessageInfo(MessageExtBrokerInner msg, int tranType) {
        // Set the storage time
        msg.setStoreTimestamp(System.currentTimeMillis());
        // Set the message body BODY CRC (consider the most appropriate setting
        // on the client)
        msg.setBodyCRC(UtilAll.crc32(msg.getBody()));

        //should be consistent with the old version
        if (tranType == MessageSysFlag.TRANSACTION_NOT_TYPE
            || tranType == MessageSysFlag.TRANSACTION_COMMIT_TYPE) {
            // Delay Delivery
            if (msg.getDelayTimeLevel() > 0) {
                if (msg.getDelayTimeLevel() > this.defaultMessageStore.getScheduleMessageService().getMaxDelayLevel()) {
                    msg.setDelayTimeLevel(this.defaultMessageStore.getScheduleMessageService().getMaxDelayLevel());
                }


                String topic = TopicValidator.RMQ_SYS_SCHEDULE_TOPIC;
                int queueId = ScheduleMessageService.delayLevel2QueueId(msg.getDelayTimeLevel());

                // Backup real topic, queueId
                MessageAccessor.putProperty(msg, MessageConst.PROPERTY_REAL_TOPIC, msg.getTopic());
                MessageAccessor.putProperty(msg, MessageConst.PROPERTY_REAL_QUEUE_ID, String.valueOf(msg.getQueueId()));
                msg.setPropertiesString(MessageDecoder.messageProperties2String(msg.getProperties()));

                msg.setTopic(topic);
                msg.setQueueId(queueId);
            }
        }

        InetSocketAddress bornSocketAddress = (InetSocketAddress) msg.getBornHost();
        if (bornSocketAddress.getAddress() instanceof Inet6Address) {
            msg.setBornHostV6Flag();
        }

        InetSocketAddress storeSocketAddress = (InetSocketAddress) msg.getStoreHost();
        if (storeSocketAddress.getAddress() instanceof Inet6Address) {
            msg.setStoreHostAddressV6Flag();
        }
    }

    /**
     * 消息追加
     * @param msg 消息
     * @return 结果
     */
    @Override
    public PutMessageResult putMessage(final MessageExtBrokerInner msg) {

        StoreStatsService storeStatsService = this.defaultMessageStore.getStoreStatsService();
        final int tranType = MessageSysFlag.getTransactionValue(msg.getSysFlag());
        String topic = msg.getTopic();
        setMessageInfo(msg,tranType);

        // Back to Results
        AppendMessageResult appendResult;
        AppendFuture<AppendEntryResponse> dledgerFuture;
        EncodeResult encodeResult;

        putMessageLock.lock(); //spin or ReentrantLock ,depending on store config
        long elapsedTimeInLock;
        long queueOffset;
        try {
            beginTimeInDledgerLock = this.defaultMessageStore.getSystemClock().now();
            encodeResult = this.messageSerializer.serialize(msg);
            queueOffset = getQueueOffsetByKey(encodeResult.queueOffsetKey, tranType);
            encodeResult.setQueueOffsetKey(queueOffset);
            if (encodeResult.status != AppendMessageStatus.PUT_OK) {
                return new PutMessageResult(PutMessageStatus.MESSAGE_ILLEGAL, new AppendMessageResult(encodeResult.status));
            }
            AppendEntryRequest request = new AppendEntryRequest();
            request.setGroup(dLedgerConfig.getGroup());
            request.setRemoteId(dLedgerServer.getMemberState().getSelfId());
            request.setBody(encodeResult.getData());
            //调用dLedgerServer#handleAppend进行追加，集群内的Leader 节点负责消息追加以及在消息复制，只有超过集群内的半数节点成功写入消息后，
            //才会返回写入成功。如果追加成功，将会返回本次追加成功后的起始偏移量，即pos属性。
            dledgerFuture = (AppendFuture<AppendEntryResponse>) dLedgerServer.handleAppend(request);
            if (dledgerFuture.getPos() == -1) {
                return new PutMessageResult(PutMessageStatus.OS_PAGECACHE_BUSY, new AppendMessageResult(AppendMessageStatus.UNKNOWN_ERROR));
            }
            //根据DLedger起始偏移量计算真正的消息的物理偏移量
            //返回给客户端的消息偏移量为body字段的开始偏移量
            //putMessage 返回的物理偏移量与不使用Dledger 方式返回的物理偏移量的含义是一样的，即从开偏移量开始，可以正确读取消息
            long wroteOffset = dledgerFuture.getPos() + DLedgerEntry.BODY_OFFSET;

            int msgIdLength = (msg.getSysFlag() & MessageSysFlag.STOREHOSTADDRESS_V6_FLAG) == 0 ? 4 + 4 + 8 : 16 + 4 + 8;
            ByteBuffer buffer = ByteBuffer.allocate(msgIdLength);

            String msgId = MessageDecoder.createMessageId(buffer, msg.getStoreHostBytes(), wroteOffset);
            elapsedTimeInLock = this.defaultMessageStore.getSystemClock().now() - beginTimeInDledgerLock;
            appendResult = new AppendMessageResult(AppendMessageStatus.PUT_OK, wroteOffset, encodeResult.getData().length, msgId, System.currentTimeMillis(), queueOffset, elapsedTimeInLock);
            switch (tranType) {
                case MessageSysFlag.TRANSACTION_PREPARED_TYPE:
                case MessageSysFlag.TRANSACTION_ROLLBACK_TYPE:
                    break;
                case MessageSysFlag.TRANSACTION_NOT_TYPE:
                case MessageSysFlag.TRANSACTION_COMMIT_TYPE:
                    // The next update ConsumeQueue information
                    DLedgerCommitLog.this.topicQueueTable.put(encodeResult.queueOffsetKey, queueOffset + 1);
                    break;
                default:
                    break;
            }
        } catch (Exception e) {
            log.error("Put message error", e);
            return new PutMessageResult(PutMessageStatus.UNKNOWN_ERROR, new AppendMessageResult(AppendMessageStatus.UNKNOWN_ERROR));
        } finally {
            beginTimeInDledgerLock = 0;
            putMessageLock.unlock();
        }

        if (elapsedTimeInLock > 500) {
            log.warn("[NOTIFYME]putMessage in lock cost time(ms)={}, bodyLength={} AppendMessageResult={}", elapsedTimeInLock, msg.getBody().length, appendResult);
        }

        PutMessageStatus putMessageStatus = PutMessageStatus.UNKNOWN_ERROR;
        try {
            AppendEntryResponse appendEntryResponse = dledgerFuture.get(3, TimeUnit.SECONDS);
            switch (DLedgerResponseCode.valueOf(appendEntryResponse.getCode())) {
                case SUCCESS:
                    putMessageStatus = PutMessageStatus.PUT_OK;
                    break;
                case INCONSISTENT_LEADER:
                case NOT_LEADER:
                case LEADER_NOT_READY:
                case DISK_FULL:
                    putMessageStatus = PutMessageStatus.SERVICE_NOT_AVAILABLE;
                    break;
                case WAIT_QUORUM_ACK_TIMEOUT:
                    //Do not return flush_slave_timeout to the client, for the ons client will ignore it.
                    putMessageStatus = PutMessageStatus.OS_PAGECACHE_BUSY;
                    break;
                case LEADER_PENDING_FULL:
                    putMessageStatus = PutMessageStatus.OS_PAGECACHE_BUSY;
                    break;
            }
        } catch (Throwable t) {
            log.error("Failed to get dledger append result", t);
        }

        PutMessageResult putMessageResult = new PutMessageResult(putMessageStatus, appendResult);
        if (putMessageStatus == PutMessageStatus.PUT_OK) {
            // Statistics
            storeStatsService.getSinglePutMessageTopicTimesTotal(msg.getTopic()).incrementAndGet();
            storeStatsService.getSinglePutMessageTopicSizeTotal(topic).addAndGet(appendResult.getWroteBytes());
        }
        return putMessageResult;
    }

    @Override
    public PutMessageResult putMessages(final MessageExtBatch messageExtBatch) {
        final int tranType = MessageSysFlag.getTransactionValue(messageExtBatch.getSysFlag());

        if (tranType != MessageSysFlag.TRANSACTION_NOT_TYPE) {
            return new PutMessageResult(PutMessageStatus.MESSAGE_ILLEGAL, null);
        }
        if (messageExtBatch.getDelayTimeLevel() > 0) {
            return new PutMessageResult(PutMessageStatus.MESSAGE_ILLEGAL, null);
        }

        // Set the storage time
        messageExtBatch.setStoreTimestamp(System.currentTimeMillis());

        StoreStatsService storeStatsService = this.defaultMessageStore.getStoreStatsService();

        InetSocketAddress bornSocketAddress = (InetSocketAddress) messageExtBatch.getBornHost();
        if (bornSocketAddress.getAddress() instanceof Inet6Address) {
            messageExtBatch.setBornHostV6Flag();
        }

        InetSocketAddress storeSocketAddress = (InetSocketAddress) messageExtBatch.getStoreHost();
        if (storeSocketAddress.getAddress() instanceof Inet6Address) {
            messageExtBatch.setStoreHostAddressV6Flag();
        }

        // Back to Results
        AppendMessageResult appendResult;
        BatchAppendFuture<AppendEntryResponse> dledgerFuture;
        EncodeResult encodeResult;

        putMessageLock.lock(); //spin or ReentrantLock ,depending on store config
        msgIdBuilder.setLength(0);
        long elapsedTimeInLock;
        long queueOffset;
        long msgNum = 0;
        try {
            beginTimeInDledgerLock = this.defaultMessageStore.getSystemClock().now();
            encodeResult = this.messageSerializer.serialize(messageExtBatch);
            queueOffset = topicQueueTable.get(encodeResult.queueOffsetKey);
            if (encodeResult.status != AppendMessageStatus.PUT_OK) {
                return new PutMessageResult(PutMessageStatus.MESSAGE_ILLEGAL, new AppendMessageResult(encodeResult
                        .status));
            }
            BatchAppendEntryRequest request = new BatchAppendEntryRequest();
            request.setGroup(dLedgerConfig.getGroup());
            request.setRemoteId(dLedgerServer.getMemberState().getSelfId());
            request.setBatchMsgs(encodeResult.batchData);
            dledgerFuture = (BatchAppendFuture<AppendEntryResponse>) dLedgerServer.handleAppend(request);
            if (dledgerFuture.getPos() == -1) {
                log.warn("HandleAppend return false due to error code {}", dledgerFuture.get().getCode());
                return new PutMessageResult(PutMessageStatus.OS_PAGECACHE_BUSY, new AppendMessageResult(AppendMessageStatus.UNKNOWN_ERROR));
            }
            long wroteOffset = 0;

            int msgIdLength = (messageExtBatch.getSysFlag() & MessageSysFlag.STOREHOSTADDRESS_V6_FLAG) == 0 ? 4 + 4 + 8 : 16 + 4 + 8;
            ByteBuffer buffer = ByteBuffer.allocate(msgIdLength);

            boolean isFirstOffset = true;
            long firstWroteOffset = 0;
            for (long pos : dledgerFuture.getPositions()) {
                wroteOffset = pos + DLedgerEntry.BODY_OFFSET;
                if (isFirstOffset) {
                    firstWroteOffset = wroteOffset;
                    isFirstOffset = false;
                }
                String msgId = MessageDecoder.createMessageId(buffer, messageExtBatch.getStoreHostBytes(), wroteOffset);
                if (msgIdBuilder.length() > 0) {
                    msgIdBuilder.append(',').append(msgId);
                } else {
                    msgIdBuilder.append(msgId);
                }
                msgNum++;
            }

            elapsedTimeInLock = this.defaultMessageStore.getSystemClock().now() - beginTimeInDledgerLock;
            appendResult = new AppendMessageResult(AppendMessageStatus.PUT_OK, firstWroteOffset, encodeResult.totalMsgLen,
                    msgIdBuilder.toString(), System.currentTimeMillis(), queueOffset, elapsedTimeInLock);
            DLedgerCommitLog.this.topicQueueTable.put(encodeResult.queueOffsetKey, queueOffset + msgNum);
        } catch (Exception e) {
            log.error("Put message error", e);
            return new PutMessageResult(PutMessageStatus.UNKNOWN_ERROR, new AppendMessageResult(AppendMessageStatus
                    .UNKNOWN_ERROR));
        } finally {
            beginTimeInDledgerLock = 0;
            putMessageLock.unlock();
        }

        if (elapsedTimeInLock > 500) {
            log.warn("[NOTIFYME]putMessage in lock cost time(ms)={}, bodyLength={} AppendMessageResult={}",
                    elapsedTimeInLock, messageExtBatch.getBody().length, appendResult);
        }

        PutMessageStatus putMessageStatus = PutMessageStatus.UNKNOWN_ERROR;
        try {
            AppendEntryResponse appendEntryResponse = dledgerFuture.get(3, TimeUnit.SECONDS);
            switch (DLedgerResponseCode.valueOf(appendEntryResponse.getCode())) {
                case SUCCESS:
                    putMessageStatus = PutMessageStatus.PUT_OK;
                    break;
                case INCONSISTENT_LEADER:
                case NOT_LEADER:
                case LEADER_NOT_READY:
                case DISK_FULL:
                    putMessageStatus = PutMessageStatus.SERVICE_NOT_AVAILABLE;
                    break;
                case WAIT_QUORUM_ACK_TIMEOUT:
                    //Do not return flush_slave_timeout to the client, for the ons client will ignore it.
                    putMessageStatus = PutMessageStatus.OS_PAGECACHE_BUSY;
                    break;
                case LEADER_PENDING_FULL:
                    putMessageStatus = PutMessageStatus.OS_PAGECACHE_BUSY;
                    break;
            }
        } catch (Throwable t) {
            log.error("Failed to get dledger append result", t);
        }

        PutMessageResult putMessageResult = new PutMessageResult(putMessageStatus, appendResult);
        if (putMessageStatus == PutMessageStatus.PUT_OK) {
            // Statistics
            storeStatsService.getSinglePutMessageTopicTimesTotal(messageExtBatch.getTopic()).addAndGet(msgNum);
            storeStatsService.getSinglePutMessageTopicSizeTotal(messageExtBatch.getTopic()).addAndGet(encodeResult.totalMsgLen);
        }
        return putMessageResult;
    }

    @Override
    public CompletableFuture<PutMessageResult> asyncPutMessage(MessageExtBrokerInner msg) {

        StoreStatsService storeStatsService = this.defaultMessageStore.getStoreStatsService();

        final int tranType = MessageSysFlag.getTransactionValue(msg.getSysFlag());

        setMessageInfo(msg, tranType);

        final String finalTopic = msg.getTopic();

        // Back to Results
        AppendMessageResult appendResult;
        AppendFuture<AppendEntryResponse> dledgerFuture;
        EncodeResult encodeResult;

        encodeResult = this.messageSerializer.serialize(msg);
        if (encodeResult.status != AppendMessageStatus.PUT_OK) {
            return CompletableFuture.completedFuture(new PutMessageResult(PutMessageStatus.MESSAGE_ILLEGAL, new AppendMessageResult(encodeResult.status)));
        }
        putMessageLock.lock(); //spin or ReentrantLock ,depending on store config
        long elapsedTimeInLock;
        long queueOffset;
        try {
            beginTimeInDledgerLock = this.defaultMessageStore.getSystemClock().now();
            queueOffset = getQueueOffsetByKey(encodeResult.queueOffsetKey, tranType);
            encodeResult.setQueueOffsetKey(queueOffset);
            AppendEntryRequest request = new AppendEntryRequest();
            request.setGroup(dLedgerConfig.getGroup());
            request.setRemoteId(dLedgerServer.getMemberState().getSelfId());
            request.setBody(encodeResult.getData());
            dledgerFuture = (AppendFuture<AppendEntryResponse>) dLedgerServer.handleAppend(request);
            if (dledgerFuture.getPos() == -1) {
                return CompletableFuture.completedFuture(new PutMessageResult(PutMessageStatus.OS_PAGECACHE_BUSY, new AppendMessageResult(AppendMessageStatus.UNKNOWN_ERROR)));
            }
            long wroteOffset = dledgerFuture.getPos() + DLedgerEntry.BODY_OFFSET;

            int msgIdLength = (msg.getSysFlag() & MessageSysFlag.STOREHOSTADDRESS_V6_FLAG) == 0 ? 4 + 4 + 8 : 16 + 4 + 8;
            ByteBuffer buffer = ByteBuffer.allocate(msgIdLength);

            String msgId = MessageDecoder.createMessageId(buffer, msg.getStoreHostBytes(), wroteOffset);
            elapsedTimeInLock = this.defaultMessageStore.getSystemClock().now() - beginTimeInDledgerLock;
            appendResult = new AppendMessageResult(AppendMessageStatus.PUT_OK, wroteOffset, encodeResult.getData().length, msgId, System.currentTimeMillis(), queueOffset, elapsedTimeInLock);
            switch (tranType) {
                case MessageSysFlag.TRANSACTION_PREPARED_TYPE:
                case MessageSysFlag.TRANSACTION_ROLLBACK_TYPE:
                    break;
                case MessageSysFlag.TRANSACTION_NOT_TYPE:
                case MessageSysFlag.TRANSACTION_COMMIT_TYPE:
                    // The next update ConsumeQueue information
                    DLedgerCommitLog.this.topicQueueTable.put(encodeResult.queueOffsetKey, queueOffset + 1);
                    break;
                default:
                    break;
            }
        } catch (Exception e) {
            log.error("Put message error", e);
            return CompletableFuture.completedFuture(new PutMessageResult(PutMessageStatus.UNKNOWN_ERROR, new AppendMessageResult(AppendMessageStatus.UNKNOWN_ERROR)));
        } finally {
            beginTimeInDledgerLock = 0;
            putMessageLock.unlock();
        }

        if (elapsedTimeInLock > 500) {
            log.warn("[NOTIFYME]putMessage in lock cost time(ms)={}, bodyLength={} AppendMessageResult={}", elapsedTimeInLock, msg.getBody().length, appendResult);
        }

        return dledgerFuture.thenApply(appendEntryResponse -> {
            PutMessageStatus putMessageStatus = PutMessageStatus.UNKNOWN_ERROR;
            switch (DLedgerResponseCode.valueOf(appendEntryResponse.getCode())) {
                case SUCCESS:
                    putMessageStatus = PutMessageStatus.PUT_OK;
                    break;
                case INCONSISTENT_LEADER:
                case NOT_LEADER:
                case LEADER_NOT_READY:
                case DISK_FULL:
                    putMessageStatus = PutMessageStatus.SERVICE_NOT_AVAILABLE;
                    break;
                case WAIT_QUORUM_ACK_TIMEOUT:
                    //Do not return flush_slave_timeout to the client, for the ons client will ignore it.
                    putMessageStatus = PutMessageStatus.OS_PAGECACHE_BUSY;
                    break;
                case LEADER_PENDING_FULL:
                    putMessageStatus = PutMessageStatus.OS_PAGECACHE_BUSY;
                    break;
            }
            PutMessageResult putMessageResult = new PutMessageResult(putMessageStatus, appendResult);
            if (putMessageStatus == PutMessageStatus.PUT_OK) {
                // Statistics
                storeStatsService.getSinglePutMessageTopicTimesTotal(finalTopic).incrementAndGet();
                storeStatsService.getSinglePutMessageTopicSizeTotal(msg.getTopic()).addAndGet(appendResult.getWroteBytes());
            }
            return putMessageResult;
        });
    }

    @Override
    public CompletableFuture<PutMessageResult> asyncPutMessages(MessageExtBatch messageExtBatch) {
        final int tranType = MessageSysFlag.getTransactionValue(messageExtBatch.getSysFlag());

        if (tranType != MessageSysFlag.TRANSACTION_NOT_TYPE) {
            return CompletableFuture.completedFuture(new PutMessageResult(PutMessageStatus.MESSAGE_ILLEGAL, null));
        }
        if (messageExtBatch.getDelayTimeLevel() > 0) {
            return CompletableFuture.completedFuture(new PutMessageResult(PutMessageStatus.MESSAGE_ILLEGAL, null));
        }

        // Set the storage time
        messageExtBatch.setStoreTimestamp(System.currentTimeMillis());

        StoreStatsService storeStatsService = this.defaultMessageStore.getStoreStatsService();

        InetSocketAddress bornSocketAddress = (InetSocketAddress) messageExtBatch.getBornHost();
        if (bornSocketAddress.getAddress() instanceof Inet6Address) {
            messageExtBatch.setBornHostV6Flag();
        }

        InetSocketAddress storeSocketAddress = (InetSocketAddress) messageExtBatch.getStoreHost();
        if (storeSocketAddress.getAddress() instanceof Inet6Address) {
            messageExtBatch.setStoreHostAddressV6Flag();
        }

        // Back to Results
        AppendMessageResult appendResult;
        BatchAppendFuture<AppendEntryResponse> dledgerFuture;
        EncodeResult encodeResult;

        encodeResult = this.messageSerializer.serialize(messageExtBatch);
        if (encodeResult.status != AppendMessageStatus.PUT_OK) {
            return CompletableFuture.completedFuture(new PutMessageResult(PutMessageStatus.MESSAGE_ILLEGAL, new AppendMessageResult(encodeResult
                    .status)));
        }

        putMessageLock.lock(); //spin or ReentrantLock ,depending on store config
        msgIdBuilder.setLength(0);
        long elapsedTimeInLock;
        long queueOffset;
        long msgNum = 0;
        try {
            beginTimeInDledgerLock = this.defaultMessageStore.getSystemClock().now();
            queueOffset = topicQueueTable.get(encodeResult.queueOffsetKey);
            BatchAppendEntryRequest request = new BatchAppendEntryRequest();
            request.setGroup(dLedgerConfig.getGroup());
            request.setRemoteId(dLedgerServer.getMemberState().getSelfId());
            request.setBatchMsgs(encodeResult.batchData);
            dledgerFuture = (BatchAppendFuture<AppendEntryResponse>) dLedgerServer.handleAppend(request);
            if (dledgerFuture.getPos() == -1) {
                log.warn("HandleAppend return false due to error code {}", dledgerFuture.get().getCode());
                return CompletableFuture.completedFuture(new PutMessageResult(PutMessageStatus.OS_PAGECACHE_BUSY, new AppendMessageResult(AppendMessageStatus.UNKNOWN_ERROR)));
            }
            long wroteOffset = 0;

            int msgIdLength = (messageExtBatch.getSysFlag() & MessageSysFlag.STOREHOSTADDRESS_V6_FLAG) == 0 ? 4 + 4 + 8 : 16 + 4 + 8;
            ByteBuffer buffer = ByteBuffer.allocate(msgIdLength);

            boolean isFirstOffset = true;
            long firstWroteOffset = 0;
            for (long pos : dledgerFuture.getPositions()) {
                wroteOffset = pos + DLedgerEntry.BODY_OFFSET;
                if (isFirstOffset) {
                    firstWroteOffset = wroteOffset;
                    isFirstOffset = false;
                }
                String msgId = MessageDecoder.createMessageId(buffer, messageExtBatch.getStoreHostBytes(), wroteOffset);
                if (msgIdBuilder.length() > 0) {
                    msgIdBuilder.append(',').append(msgId);
                } else {
                    msgIdBuilder.append(msgId);
                }
                msgNum++;
            }

            elapsedTimeInLock = this.defaultMessageStore.getSystemClock().now() - beginTimeInDledgerLock;
            appendResult = new AppendMessageResult(AppendMessageStatus.PUT_OK, firstWroteOffset, encodeResult.totalMsgLen,
                    msgIdBuilder.toString(), System.currentTimeMillis(), queueOffset, elapsedTimeInLock);
            DLedgerCommitLog.this.topicQueueTable.put(encodeResult.queueOffsetKey, queueOffset + msgNum);
        } catch (Exception e) {
            log.error("Put message error", e);
            return CompletableFuture.completedFuture(new PutMessageResult(PutMessageStatus.UNKNOWN_ERROR, new AppendMessageResult(AppendMessageStatus.UNKNOWN_ERROR)));
        } finally {
            beginTimeInDledgerLock = 0;
            putMessageLock.unlock();
        }

        if (elapsedTimeInLock > 500) {
            log.warn("[NOTIFYME]putMessage in lock cost time(ms)={}, bodyLength={} AppendMessageResult={}",
                    elapsedTimeInLock, messageExtBatch.getBody().length, appendResult);
        }

        return dledgerFuture.thenApply(appendEntryResponse -> {
            PutMessageStatus putMessageStatus = PutMessageStatus.UNKNOWN_ERROR;
            switch (DLedgerResponseCode.valueOf(appendEntryResponse.getCode())) {
                case SUCCESS:
                    putMessageStatus = PutMessageStatus.PUT_OK;
                    break;
                case INCONSISTENT_LEADER:
                case NOT_LEADER:
                case LEADER_NOT_READY:
                case DISK_FULL:
                    putMessageStatus = PutMessageStatus.SERVICE_NOT_AVAILABLE;
                    break;
                case WAIT_QUORUM_ACK_TIMEOUT:
                    //Do not return flush_slave_timeout to the client, for the ons client will ignore it.
                    putMessageStatus = PutMessageStatus.OS_PAGECACHE_BUSY;
                    break;
                case LEADER_PENDING_FULL:
                    putMessageStatus = PutMessageStatus.OS_PAGECACHE_BUSY;
                    break;
            }
            PutMessageResult putMessageResult = new PutMessageResult(putMessageStatus, appendResult);
            if (putMessageStatus == PutMessageStatus.PUT_OK) {
                // Statistics
                storeStatsService.getSinglePutMessageTopicTimesTotal(messageExtBatch.getTopic()).incrementAndGet();
                storeStatsService.getSinglePutMessageTopicSizeTotal(messageExtBatch.getTopic()).addAndGet(appendResult.getWroteBytes());
            }
            return putMessageResult;
        });
    }

    /**
     * 根据偏移量读取消息
     * @param offset 偏移量
     * @param size 长度
     * @return 结果
     */
    @Override
    public SelectMappedBufferResult getMessage(final long offset, final int size) {
        //小于CommitLog最大偏移量，从CommitLog中查找
        if (offset < dividedCommitlogOffset) {
            return super.getMessage(offset, size);
        }
        int mappedFileSize = this.dLedgerServer.getdLedgerConfig().getMappedFileSizeForEntryData();
        //根据偏移量寻找文件
        MmapFile mappedFile = this.dLedgerFileList.findMappedFileByOffset(offset, offset == 0);
        if (mappedFile != null) {
            int pos = (int) (offset % mappedFileSize);
            //返回查找的消息
            return convertSbr(mappedFile.selectMappedBuffer(pos, size));
        }
        return null;
    }

    @Override
    public long rollNextFile(final long offset) {
        int mappedFileSize = this.defaultMessageStore.getMessageStoreConfig().getMappedFileSizeCommitLog();
        return offset + mappedFileSize - offset % mappedFileSize;
    }

    @Override
    public HashMap<String, Long> getTopicQueueTable() {
        return topicQueueTable;
    }

    @Override
    public void setTopicQueueTable(HashMap<String, Long> topicQueueTable) {
        this.topicQueueTable = topicQueueTable;
    }

    @Override
    public void destroy() {
        super.destroy();
        dLedgerFileList.destroy();
    }

    @Override
    public boolean appendData(long startOffset, byte[] data) {
        //the old ha service will invoke method, here to prevent it
        return false;
    }

    @Override
    public void checkSelf() {
        dLedgerFileList.checkSelf();
    }

    @Override
    public long lockTimeMills() {
        long diff = 0;
        long begin = this.beginTimeInDledgerLock;
        if (begin > 0) {
            diff = this.defaultMessageStore.now() - begin;
        }

        if (diff < 0) {
            diff = 0;
        }

        return diff;
    }

    private long getQueueOffsetByKey(String key, int tranType) {
        Long queueOffset = DLedgerCommitLog.this.topicQueueTable.get(key);
        if (null == queueOffset) {
            queueOffset = 0L;
            DLedgerCommitLog.this.topicQueueTable.put(key, queueOffset);
        }

        // Transaction messages that require special handling
        switch (tranType) {
            // Prepared and Rollback message is not consumed, will not enter the
            // consumer queuec
            case MessageSysFlag.TRANSACTION_PREPARED_TYPE:
            case MessageSysFlag.TRANSACTION_ROLLBACK_TYPE:
                queueOffset = 0L;
                break;
            case MessageSysFlag.TRANSACTION_NOT_TYPE:
            case MessageSysFlag.TRANSACTION_COMMIT_TYPE:
            default:
                break;
        }
        return queueOffset;
    }


    class EncodeResult {
        private String queueOffsetKey;
        private ByteBuffer data;
        private List<byte[]> batchData;
        private AppendMessageStatus status;
        private int totalMsgLen;

        public EncodeResult(AppendMessageStatus status, ByteBuffer data, String queueOffsetKey) {
            this.data = data;
            this.status = status;
            this.queueOffsetKey = queueOffsetKey;
        }

        public void setQueueOffsetKey(long offset) {
            data.putLong(MessageDecoder.QUEUE_OFFSET_POSITION, offset);
        }

        public byte[] getData() {
            return data.array();
        }

        public EncodeResult(AppendMessageStatus status, String queueOffsetKey, List<byte[]> batchData, int totalMsgLen) {
            this.batchData = batchData;
            this.status = status;
            this.queueOffsetKey = queueOffsetKey;
            this.totalMsgLen = totalMsgLen;
        }
    }

    class MessageSerializer {

        // The maximum length of the message
        private final int maxMessageSize;
        // Build Message Key
        private final StringBuilder keyBuilder = new StringBuilder();

        MessageSerializer(final int size) {
            this.maxMessageSize = size;
        }

        public EncodeResult serialize(final MessageExtBrokerInner msgInner) {
            // STORETIMESTAMP + STOREHOSTADDRESS + OFFSET <br>

            // PHY OFFSET
            long wroteOffset = 0;

            long queueOffset = 0;

            int sysflag = msgInner.getSysFlag();

            int bornHostLength = (sysflag & MessageSysFlag.BORNHOST_V6_FLAG) == 0 ? 4 + 4 : 16 + 4;
            int storeHostLength = (sysflag & MessageSysFlag.STOREHOSTADDRESS_V6_FLAG) == 0 ? 4 + 4 : 16 + 4;
            ByteBuffer bornHostHolder = ByteBuffer.allocate(bornHostLength);
            ByteBuffer storeHostHolder = ByteBuffer.allocate(storeHostLength);

            String key = msgInner.getTopic() + "-" + msgInner.getQueueId();

            /**
             * Serialize message
             */
            final byte[] propertiesData =
                msgInner.getPropertiesString() == null ? null : msgInner.getPropertiesString().getBytes(MessageDecoder.CHARSET_UTF8);

            final int propertiesLength = propertiesData == null ? 0 : propertiesData.length;

            if (propertiesLength > Short.MAX_VALUE) {
                log.warn("putMessage message properties length too long. length={}", propertiesData.length);
                return new EncodeResult(AppendMessageStatus.PROPERTIES_SIZE_EXCEEDED, null, key);
            }

            final byte[] topicData = msgInner.getTopic().getBytes(MessageDecoder.CHARSET_UTF8);
            final int topicLength = topicData.length;

            final int bodyLength = msgInner.getBody() == null ? 0 : msgInner.getBody().length;

            final int msgLen = calMsgLength(msgInner.getSysFlag(), bodyLength, topicLength, propertiesLength);

            ByteBuffer msgStoreItemMemory = ByteBuffer.allocate(msgLen);

            // Exceeds the maximum message
            if (msgLen > this.maxMessageSize) {
                DLedgerCommitLog.log.warn("message size exceeded, msg total size: " + msgLen + ", msg body size: " + bodyLength
                    + ", maxMessageSize: " + this.maxMessageSize);
                return new EncodeResult(AppendMessageStatus.MESSAGE_SIZE_EXCEEDED, null, key);
            }
            // Initialization of storage space
            this.resetByteBuffer(msgStoreItemMemory, msgLen);
            // 1 TOTALSIZE
            msgStoreItemMemory.putInt(msgLen);
            // 2 MAGICCODE
            msgStoreItemMemory.putInt(DLedgerCommitLog.MESSAGE_MAGIC_CODE);
            // 3 BODYCRC
            msgStoreItemMemory.putInt(msgInner.getBodyCRC());
            // 4 QUEUEID
            msgStoreItemMemory.putInt(msgInner.getQueueId());
            // 5 FLAG
            msgStoreItemMemory.putInt(msgInner.getFlag());
            // 6 QUEUEOFFSET
            msgStoreItemMemory.putLong(queueOffset);
            // 7 PHYSICALOFFSET
            msgStoreItemMemory.putLong(wroteOffset);
            // 8 SYSFLAG
            msgStoreItemMemory.putInt(msgInner.getSysFlag());
            // 9 BORNTIMESTAMP
            msgStoreItemMemory.putLong(msgInner.getBornTimestamp());
            // 10 BORNHOST
            resetByteBuffer(bornHostHolder, bornHostLength);
            msgStoreItemMemory.put(msgInner.getBornHostBytes(bornHostHolder));
            // 11 STORETIMESTAMP
            msgStoreItemMemory.putLong(msgInner.getStoreTimestamp());
            // 12 STOREHOSTADDRESS
            resetByteBuffer(storeHostHolder, storeHostLength);
            msgStoreItemMemory.put(msgInner.getStoreHostBytes(storeHostHolder));
            //this.msgBatchMemory.put(msgInner.getStoreHostBytes());
            // 13 RECONSUMETIMES
            msgStoreItemMemory.putInt(msgInner.getReconsumeTimes());
            // 14 Prepared Transaction Offset
            msgStoreItemMemory.putLong(msgInner.getPreparedTransactionOffset());
            // 15 BODY
            msgStoreItemMemory.putInt(bodyLength);
            if (bodyLength > 0) {
                msgStoreItemMemory.put(msgInner.getBody());
            }
            // 16 TOPIC
            msgStoreItemMemory.put((byte) topicLength);
            msgStoreItemMemory.put(topicData);
            // 17 PROPERTIES
            msgStoreItemMemory.putShort((short) propertiesLength);
            if (propertiesLength > 0) {
                msgStoreItemMemory.put(propertiesData);
            }
            return new EncodeResult(AppendMessageStatus.PUT_OK, msgStoreItemMemory, key);
        }

        public EncodeResult serialize(final MessageExtBatch messageExtBatch) {
            keyBuilder.setLength(0);
            keyBuilder.append(messageExtBatch.getTopic());
            keyBuilder.append('-');
            keyBuilder.append(messageExtBatch.getQueueId());
            String key = keyBuilder.toString();

            Long queueOffset = DLedgerCommitLog.this.topicQueueTable.get(key);
            if (null == queueOffset) {
                queueOffset = 0L;
                DLedgerCommitLog.this.topicQueueTable.put(key, queueOffset);
            }

            int totalMsgLen = 0;
            ByteBuffer messagesByteBuff = messageExtBatch.wrap();
            List<byte[]> batchBody = new LinkedList<>();

            int sysFlag = messageExtBatch.getSysFlag();
            int bornHostLength = (sysFlag & MessageSysFlag.BORNHOST_V6_FLAG) == 0 ? 4 + 4 : 16 + 4;
            int storeHostLength = (sysFlag & MessageSysFlag.STOREHOSTADDRESS_V6_FLAG) == 0 ? 4 + 4 : 16 + 4;
            ByteBuffer bornHostHolder = ByteBuffer.allocate(bornHostLength);
            ByteBuffer storeHostHolder = ByteBuffer.allocate(storeHostLength);

            while (messagesByteBuff.hasRemaining()) {
                // 1 TOTALSIZE
                messagesByteBuff.getInt();
                // 2 MAGICCODE
                messagesByteBuff.getInt();
                // 3 BODYCRC
                messagesByteBuff.getInt();
                // 4 FLAG
                int flag = messagesByteBuff.getInt();
                // 5 BODY
                int bodyLen = messagesByteBuff.getInt();
                int bodyPos = messagesByteBuff.position();
                int bodyCrc = UtilAll.crc32(messagesByteBuff.array(), bodyPos, bodyLen);
                messagesByteBuff.position(bodyPos + bodyLen);
                // 6 properties
                short propertiesLen = messagesByteBuff.getShort();
                int propertiesPos = messagesByteBuff.position();
                messagesByteBuff.position(propertiesPos + propertiesLen);

                final byte[] topicData = messageExtBatch.getTopic().getBytes(MessageDecoder.CHARSET_UTF8);

                final int topicLength = topicData.length;

                final int msgLen = calMsgLength(messageExtBatch.getSysFlag(), bodyLen, topicLength, propertiesLen);
                ByteBuffer msgStoreItemMemory = ByteBuffer.allocate(msgLen);

                // Exceeds the maximum message
                if (msgLen > this.maxMessageSize) {
                    CommitLog.log.warn("message size exceeded, msg total size: " + msgLen + ", msg body size: " +
                            bodyLen
                            + ", maxMessageSize: " + this.maxMessageSize);
                    throw new RuntimeException("message size exceeded");
                }

                totalMsgLen += msgLen;
                // Determines whether there is sufficient free space
                if (totalMsgLen > maxMessageSize) {
                    throw new RuntimeException("message size exceeded");
                }

                // Initialization of storage space
                this.resetByteBuffer(msgStoreItemMemory, msgLen);
                // 1 TOTALSIZE
                msgStoreItemMemory.putInt(msgLen);
                // 2 MAGICCODE
                msgStoreItemMemory.putInt(DLedgerCommitLog.MESSAGE_MAGIC_CODE);
                // 3 BODYCRC
                msgStoreItemMemory.putInt(bodyCrc);
                // 4 QUEUEID
                msgStoreItemMemory.putInt(messageExtBatch.getQueueId());
                // 5 FLAG
                msgStoreItemMemory.putInt(flag);
                // 6 QUEUEOFFSET
                msgStoreItemMemory.putLong(queueOffset++);
                // 7 PHYSICALOFFSET
                msgStoreItemMemory.putLong(0);
                // 8 SYSFLAG
                msgStoreItemMemory.putInt(messageExtBatch.getSysFlag());
                // 9 BORNTIMESTAMP
                msgStoreItemMemory.putLong(messageExtBatch.getBornTimestamp());
                // 10 BORNHOST
                resetByteBuffer(bornHostHolder, bornHostLength);
                msgStoreItemMemory.put(messageExtBatch.getBornHostBytes(bornHostHolder));
                // 11 STORETIMESTAMP
                msgStoreItemMemory.putLong(messageExtBatch.getStoreTimestamp());
                // 12 STOREHOSTADDRESS
                resetByteBuffer(storeHostHolder, storeHostLength);
                msgStoreItemMemory.put(messageExtBatch.getStoreHostBytes(storeHostHolder));
                // 13 RECONSUMETIMES
                msgStoreItemMemory.putInt(messageExtBatch.getReconsumeTimes());
                // 14 Prepared Transaction Offset
                msgStoreItemMemory.putLong(0);
                // 15 BODY
                msgStoreItemMemory.putInt(bodyLen);
                if (bodyLen > 0) {
                    msgStoreItemMemory.put(messagesByteBuff.array(), bodyPos, bodyLen);
                }
                // 16 TOPIC
                msgStoreItemMemory.put((byte) topicLength);
                msgStoreItemMemory.put(topicData);
                // 17 PROPERTIES
                msgStoreItemMemory.putShort(propertiesLen);
                if (propertiesLen > 0) {
                    msgStoreItemMemory.put(messagesByteBuff.array(), propertiesPos, propertiesLen);
                }
                byte[] data = new byte[msgLen];
                msgStoreItemMemory.clear();
                msgStoreItemMemory.get(data);
                batchBody.add(data);
            }

            return new EncodeResult(AppendMessageStatus.PUT_OK, key, batchBody, totalMsgLen);
        }

        private void resetByteBuffer(final ByteBuffer byteBuffer, final int limit) {
            byteBuffer.flip();
            byteBuffer.limit(limit);
        }
    }

    public static class DLedgerSelectMappedBufferResult extends SelectMappedBufferResult {

        private SelectMmapBufferResult sbr;

        public DLedgerSelectMappedBufferResult(SelectMmapBufferResult sbr) {
            super(sbr.getStartOffset(), sbr.getByteBuffer(), sbr.getSize(), null);
            this.sbr = sbr;
        }

        public synchronized void release() {
            super.release();
            if (sbr != null) {
                sbr.release();
            }
        }

    }

    public DLedgerServer getdLedgerServer() {
        return dLedgerServer;
    }

    public int getId() {
        return id;
    }

    public long getDividedCommitlogOffset() {
        return dividedCommitlogOffset;
    }
}
