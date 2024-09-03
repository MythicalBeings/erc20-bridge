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

import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.methods.response.TransactionReceipt;
import org.web3j.protocol.exceptions.TransactionException;
import org.web3j.tx.response.Callback;
import org.web3j.tx.response.QueuingTransactionReceiptProcessor;

import java.io.IOException;

/**
 * Holds an instance of {@link RetryCallback} provided to the constructor, which keeps track of all created
 * {@link RetryingRawTransactionManager}s
 * <p>
 * Overrides {@link #waitForTransactionReceipt(String)} to create a {@link FixedEmptyTransactionReceipt}
 * instead of {@link org.web3j.tx.response.EmptyTransactionReceipt}.
 * See <a href="https://github.com/web3j/web3j/issues/1207">this post</a>.
 *
 */
public class RetryReceiptProcessor extends QueuingTransactionReceiptProcessor {
    private RetryCallback callback;
    public RetryReceiptProcessor(Web3j web3j, RetryCallback callback, int pollingAttemptsPerTxHash, long pollingFrequency) {
        super(web3j, callback, pollingAttemptsPerTxHash, pollingFrequency);
        this.callback = callback;
    }

    RetryCallback getCallback() {
        return callback;
    }

    @Override
    public TransactionReceipt waitForTransactionReceipt(String transactionHash) throws IOException, TransactionException {
        super.waitForTransactionReceipt(transactionHash);
        return new FixedEmptyTransactionReceipt(transactionHash);
    }
}
