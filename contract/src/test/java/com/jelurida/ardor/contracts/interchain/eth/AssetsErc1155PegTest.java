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
package com.jelurida.ardor.contracts.interchain.eth;

import com.jelurida.web3j.generated.BRIDGE_ERC20;
import com.jelurida.web3j.erc20.utils.txman.RetryingRawTransactionManager;
import com.jelurida.web3j.generated.IERC20;
import nxt.Tester;
import nxt.addons.JO;
import nxt.http.callers.GetAccountAssetsCall;
import nxt.http.callers.GetAssetAccountCountCall;
import nxt.http.callers.IssueAssetCall;
import nxt.http.callers.TransferAssetCall;
import nxt.util.Convert;
import nxt.util.Logger;
import org.jetbrains.annotations.NotNull;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.Hash;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.response.TransactionReceipt;
import org.web3j.rlp.RlpEncoder;
import org.web3j.rlp.RlpList;
import org.web3j.rlp.RlpString;
import org.web3j.tx.Contract;
import org.web3j.tx.gas.ContractGasProvider;
import org.web3j.tx.gas.StaticGasProvider;
import org.web3j.utils.Numeric;

import java.io.IOException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static nxt.blockchain.ChildChain.IGNIS;

public class AssetsErc1155PegTest extends BasePegTest {
    protected IERC20 wETH;
    private RetryingRawTransactionManager ebaTransactionManager;
    private RetryingRawTransactionManager senderTransactionManager;
    private static final BigInteger QNT_FACTOR = new BigInteger("100000000");

    @Before
    public void beforeTest() throws Exception {
        super.beforeTest();

        ebaTransactionManager = createTransactionManager(ethBlockedAcc);
        senderTransactionManager = createTransactionManager(ethDeployAcc);

        wETH = IERC20.load(paramsJo.getString("contractAddress"), web3j, senderTransactionManager, createCurrentPriceGasProvider(web3j, BigInteger.valueOf(4_000_000)));
        Logger.logInfoMessage("TESTING | beforeTest | wETH Address: " + wETH.getContractAddress());
    }

    @Test
    public void test() {
        try {
            Tester wrapper = DAVE;

            BigInteger balance = getAssetBalance(wrapper);
            Assert.assertEquals(BigInteger.ZERO, balance);

            // ##################################
            // WRAP: EVM to Ardor
            // ##################################
            // Testing with 1 TX
            generateEVMtoArdorWraps(wrapper, 1);
            balance = getAssetBalance(wrapper);
            Assert.assertEquals(QNT_FACTOR.multiply(BigInteger.valueOf(1)), balance);
            // --------------------
            // Testing with 3 TX
            generateEVMtoArdorWraps(wrapper, 3);
            balance = getAssetBalance(wrapper);
            Assert.assertEquals(QNT_FACTOR.multiply(BigInteger.valueOf(4)), balance);

            // ##################################
            // Unwrap: Ardor to EVM
            // ##################################
            sendAssetFromOwner(CHUCK, 5);
            sendAssetForUnwrapping(CHUCK, 1);

            Assert.assertEquals("success", waitUnwrapping(1));
            sendAssetForUnwrapping(CHUCK, 1);

            // WHY COUNT IS 2? - Should be 1
            Assert.assertEquals("success", waitUnwrapping(2));

            sendAssetForUnwrapping(CHUCK, 3);
            // Now is 3
            Assert.assertEquals("success", waitUnwrapping(3));


        } catch (Exception e) {
            Logger.logInfoMessage("MB-ERC20 | test | WRAPPING ERROR in CATCH: " + e.getMessage());
        }
    }

    private String waitUnwrapping(int count) {
        while (true) {
            List<JO> unwrappingLog = getUnwrappingLog();
            Logger.logInfoMessage("MB-ERC20 | waitUnwrapping | wrappingLog.size(): " + unwrappingLog.size());
            Assert.assertEquals(count, unwrappingLog.size());

            Optional<JO> error = unwrappingLog.stream().filter(log -> log.get("error") != null).findFirst();
            if (error.isPresent()) {
                return (String) error.get().get("error");
            }

            if (unwrappingLog.stream().allMatch(log -> log.get("success") != null)) {
                return "success";
            }
            try {
                Thread.sleep(2000);
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }
        }
    }

    private void generateEVMtoArdorWraps(Tester wrapper, int amountOfTxs) {
        try {
            String wrapDepositAddress = getWrapDepositAddress(wrapper);
            generateEthWrapTx(wrapDepositAddress, amountOfTxs);
            int numWraps = processWraps(wrapper);
            Assert.assertEquals(1, numWraps);
            List<String> fullHashes = waitForUnconfirmedAssetTransfers(wrapper, numWraps);
            generateBlock();
            confirmArdorTransactions(fullHashes);
        } catch (Exception e) {
            Logger.logInfoMessage("TESTING | test | generateEVMtoArdorWraps FAILED: " + e.getMessage());
        }
    }

    private void generateEthWrapTx(String wrapDepositAddress, int amountOfTxs) {
        try {
            for (int i = 0; i < amountOfTxs; i++) {
                TransactionReceipt sendToWrapTx = wETH.transfer(wrapDepositAddress, new BigInteger("1000000000000000000")).send();
                Assert.assertTrue(sendToWrapTx.isStatusOK());
                Logger.logInfoMessage("TESTING | test | generateEthWrapTx: " + sendToWrapTx.getTransactionHash());
            }
        } catch (Exception e) {
            Logger.logInfoMessage("TESTING | test | generateEthWrapTx FAILED: " + e.getMessage());
        }
    }

    private List<JO> getUnwrappingLog() {
        return contractRequest("mbGetUnwrappingLog").callNoError().getJoList("log");
    }

    @NotNull
    private ContractGasProvider createCurrentPriceGasProvider(Web3j web3j, BigInteger gasLimit) throws IOException {
        BigInteger gasPrice = web3j.ethGasPrice().send().getGasPrice();
        return new StaticGasProvider(gasPrice, gasLimit);
    }

    private void sendAsset(Tester sender, Tester receiver, int quantityQNT) {
        String assetId = paramsJo.getString("assetId");
        TransferAssetCall.create(IGNIS.getId())
                .asset(assetId)
                .privateKey(sender.getPrivateKey())
                .recipient(receiver.getId())
                .quantityQNT(quantityQNT)
                .feeNQT(IGNIS.ONE_COIN)
                .callNoError();
        generateBlock();
    }

    private BigInteger getAssetBalance(Tester receiver) {
        String assetId = paramsJo.getString("assetId");
        String account = receiver.getRsAccount();
        JO test = GetAccountAssetsCall.create()
                .asset(assetId)
                .account(account)
                .callNoError();
        return test.isExist("unconfirmedQuantityQNT") ? BigInteger.valueOf(test.getInt("unconfirmedQuantityQNT")) : BigInteger.ZERO;
    }

    private void sendAssetFromOwner(Tester receiver, int quantityQNT) {
        String assetId = paramsJo.getString("assetId");
        Tester owner = new Tester("hope peace happen touch easy pretend worthless talk them indeed wheel state");
        TransferAssetCall.create(IGNIS.getId())
                .asset(assetId)
                .privateKey(owner.getPrivateKey())
                .recipient(receiver.getId())
                .quantityQNT(quantityQNT)
                .feeNQT(IGNIS.ONE_COIN)
                .callNoError();
        generateBlock();
    }

    private void sendAssetForUnwrapping(Tester sender, int quantityQNT) {
        String assetId = paramsJo.getString("assetId");
        Credentials senderEthAcc = generateTesterEthAcc(sender);
        Tester owner = new Tester("hope peace happen touch easy pretend worthless talk them indeed wheel state");

        TransferAssetCall.create(IGNIS.getId())
                .asset(assetId)
                .privateKey(sender.getPrivateKey())
                .recipient(owner.getId())
                .quantityQNT(quantityQNT)
                .messageToEncrypt(senderEthAcc.getAddress())
                .feeNQT(IGNIS.ONE_COIN)
                .callNoError();
        generateBlocks(paramsJo.getInt("ardorConfirmations") + 1);
    }

    @NotNull
    private Credentials generateTesterEthAcc(Tester tester) {
        return AssetsErc20.getCredentialsFromSecret("User's secret on Eth side " + tester.getSecretPhrase());
    }

}