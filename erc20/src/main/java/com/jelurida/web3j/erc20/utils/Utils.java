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

package com.jelurida.web3j.erc20.utils;

import com.jelurida.web3j.generated.IERC20;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.web3j.abi.EventValues;
import org.web3j.abi.FunctionEncoder;
import org.web3j.abi.datatypes.Function;
import org.web3j.abi.datatypes.Type;
import org.web3j.abi.datatypes.generated.Uint256;
import org.web3j.protocol.core.methods.response.Transaction;
import org.web3j.utils.Numeric;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collections;

public class Utils {
    static final Logger log = LoggerFactory.getLogger(Utils.class);

    public static byte[] getSafeTransferData(Transaction transaction) {
        Function function = new Function(
                IERC20.FUNC_TRANSFER,
                Arrays.asList(new org.web3j.abi.datatypes.Address(160, BigInteger.ZERO), //from
                        new org.web3j.abi.datatypes.Address(160, BigInteger.ZERO), //to
                        new org.web3j.abi.datatypes.generated.Uint256(BigInteger.ZERO),//id
                        new org.web3j.abi.datatypes.generated.Uint256(BigInteger.ZERO), //amount
                        new org.web3j.abi.datatypes.DynamicBytes(new byte[]{})), //the data we are extracting
                Collections.emptyList());
        return getTransactionData(transaction, function, 4);
    }

    public static byte[] getTransactionData(Transaction transaction, Function function, int dataParameterIndex) {
        String functionTemplate = FunctionEncoder.encode(function);

        String transactionInput = transaction.getInput();
        if (functionTemplate.substring(0, 10).equals(transactionInput.substring(0, 10))) {
            String parameters = transactionInput.substring(10);

            int intCharsLength = Type.MAX_BYTE_LENGTH * 2;
            int dataIndex = dataParameterIndex * intCharsLength;
            int dynamicDataOffset = Numeric.decodeQuantity("0x" + parameters.substring(dataIndex,
                    dataIndex + intCharsLength)).intValueExact() * 2;
            int dataSize = Numeric.decodeQuantity("0x" + parameters.substring(dynamicDataOffset,
                    dynamicDataOffset + intCharsLength)).intValueExact() * 2;
            dynamicDataOffset += intCharsLength;

            return Numeric.hexStringToByteArray(parameters.substring(dynamicDataOffset, dynamicDataOffset + dataSize));
        } else {
            log.warn("Transaction " + transaction.getHash() + " input is not calling the " + function.getName() + " method");
            return null;
        }
    }

    public static BigInteger parseTokenId(String tokenIdString) {
        if (tokenIdString.startsWith("0x")) {
            return Numeric.decodeQuantity(tokenIdString);
        }
        return new BigInteger(tokenIdString);
    }

    public static long timestampToMillis(BigInteger timestamp) {
        return timestamp.longValue() * 1000L;
    }

    public static Function createSetApprovalForAllFunction(String operator, BigInteger amount) {
        return new Function(
                IERC20.FUNC_APPROVE,
                Arrays.asList(new org.web3j.abi.datatypes.Address(160, operator),
                        new org.web3j.abi.datatypes.Int(amount)),
                Collections.emptyList());
    }

    public static BigInteger getEventValueBigInteger(EventValues eventValues, int valueIndex) {
        Uint256 uint256 = (Uint256) eventValues.getNonIndexedValues().get(valueIndex);
        return uint256.getValue();
    }
}
