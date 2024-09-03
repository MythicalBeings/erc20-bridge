/*
 * Copyright © 2021 Jelurida IP B.V.
 *
 * See the LICENSE.txt file at the top-level directory of this distribution
 * for licensing information.
 *
 * Unless otherwise agreed in a custom licensing agreement with Jelurida B.V.,
 * no part of this software, including this file, may be copied, modified,
 * propagated, or distributed except according to the terms contained in the
 * LICENSE.txt file.
 *
 * Removal or modification of this copyright notice is prohibited.
 *
 */

package com.jelurida.web3j.erc20.utils.txman;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.web3j.protocol.core.methods.response.TransactionReceipt;
import org.web3j.protocol.exceptions.TransactionException;
import org.web3j.tx.response.Callback;

import java.util.ArrayList;
import java.util.List;

public class RetryCallback implements Callback {
    static final Logger log = LoggerFactory.getLogger(RetryCallback.class);
    private final List<RetryingRawTransactionManager> transactionManagers = new ArrayList<>();

    @Override
    public void accept(TransactionReceipt transactionReceipt) {
        for (RetryingRawTransactionManager tm : transactionManagers) {
            if (tm.hasPendingTransaction(transactionReceipt.getTransactionHash())) {
                tm.transactionComplete(transactionReceipt);
                return;
            }
        }
        log.warn("Transaction already removed from pending set of all transaction managers " +
                transactionReceipt.getTransactionHash() + " managers count=" + transactionManagers.size());
    }

    @Override
    public void exception(Exception e) {
        RetryingRawTransactionManager.log.error("Exception when creating Ethereum transaction", e);
        if (e instanceof TransactionException) {
            ((TransactionException) e).getTransactionHash().ifPresent(hash -> {
                for (RetryingRawTransactionManager tm : transactionManagers) {
                    if (tm.hasPendingTransaction(hash)) {
                        tm.retryTimedOutTransaction(hash, true);
                    }
                }
            });
        }
    }

    public void addTransactionManager(RetryingRawTransactionManager transactionManager) {
        this.transactionManagers.add(transactionManager);
    }

    public void removeTransactionManager(RetryingRawTransactionManager transactionManager) {
        this.transactionManagers.remove(transactionManager);
    }
}
