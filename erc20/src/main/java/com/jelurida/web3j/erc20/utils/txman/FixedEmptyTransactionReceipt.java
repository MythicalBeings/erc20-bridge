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

import org.web3j.tx.response.EmptyTransactionReceipt;

//We cannot use generated wrappers with QueuingTransactionReceiptProcessor unless we override isStatusOK to not
// throw
//See https://github.com/web3j/web3j/issues/1207
public class FixedEmptyTransactionReceipt extends EmptyTransactionReceipt {
    public FixedEmptyTransactionReceipt(String transactionHash) {
        super(transactionHash);
    }

    @Override
    public boolean isStatusOK() {
        return true;
    }
}
