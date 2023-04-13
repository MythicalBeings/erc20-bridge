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

package com.jelurida.web3j.utils.txman;

import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.methods.response.TransactionReceipt;
import org.web3j.protocol.exceptions.TransactionException;
import org.web3j.tx.response.Callback;
import org.web3j.tx.response.QueuingTransactionReceiptProcessor;

import java.io.IOException;

/**
 * Only override {@link #waitForTransactionReceipt(String)} to create a {@link FixedEmptyTransactionReceipt}
 * instead of {@link org.web3j.tx.response.EmptyTransactionReceipt}
 *
 * See https://github.com/web3j/web3j/issues/1207
 */
public class FixedReceiptProcessor extends QueuingTransactionReceiptProcessor {
    public FixedReceiptProcessor(Web3j web3j, Callback callback, int pollingAttemptsPerTxHash, long pollingFrequency) {
        super(web3j, callback, pollingAttemptsPerTxHash, pollingFrequency);
    }

    @Override
    public TransactionReceipt waitForTransactionReceipt(String transactionHash) throws IOException, TransactionException {
        super.waitForTransactionReceipt(transactionHash);
        return new FixedEmptyTransactionReceipt(transactionHash);
    }
}
