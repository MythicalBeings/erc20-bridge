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

import com.jelurida.ardor.contracts.AbstractContractTest;
import com.jelurida.ardor.contracts.ContractTestHelper;
import com.jelurida.ardor.contracts.TestApiAddOn;
import com.jelurida.web3j.erc20.utils.txman.RetryingRawTransactionManager;
import nxt.Tester;
import nxt.addons.AddOns;
import nxt.addons.ContractRunner;
import nxt.addons.JA;
import nxt.addons.JO;
import nxt.http.callers.GetTransactionCall;
import nxt.http.callers.GetUnconfirmedTransactionsCall;
import nxt.http.callers.IssueAssetCall;
import nxt.http.callers.TriggerContractByRequestCall;
import nxt.util.Convert;
import nxt.util.Logger;
import org.jetbrains.annotations.NotNull;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.slf4j.helpers.SubstituteLogger;
import org.web3j.crypto.Credentials;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.methods.response.TransactionReceipt;
import org.web3j.protocol.http.HttpService;

import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static nxt.blockchain.ChildChain.IGNIS;

public class BasePegTest extends AbstractContractTest {
    public static final String RUNNER_CONFIG_FILE = "../contract/src/test/resources/test_contract_config.json";
    protected JO configJo;
    protected JO paramsJo;
    protected Web3j web3j;

    protected Credentials ethBlockedAcc;
    protected Credentials ethDeployAcc;

    @BeforeClass
    public static void init() {
        initPegContractTest();
    }

    protected static void initPegContractTest() {
        Map<String, String> properties = new HashMap();
        properties.put("nxt.disableSecurityPolicy", "true");
        //properties.put("nxt.defaultChildBlockDeadline", "1");
        properties.put("nxt.addOns", "nxt.addons.ContractRunner;" + TestApiAddOn.class.getName());
        properties.put("addon.contractRunner.configFile", RUNNER_CONFIG_FILE);
        properties.put("addon.contractRunner.secretPhrase", "hope peace happen touch easy pretend worthless talk them indeed wheel state");
        properties.put("addon.contractRunner.feeRateNQTPerFXT.IGNIS", "200000000");
        properties.put("addon.contractRunner.feeRateNQTPerFXT.AEUR", "20000");
        properties.put("addon.contractRunner.defaultDeadline", String.valueOf(25));
        properties.put("nxt.testnetLeasingDelay", "2");
        properties.put("nxt.isLightClient", "false");
        properties.put("contract.manager.secretPhrase", "hope peace happen touch easy pretend worthless talk them indeed wheel state");
        properties.put("contract.manager.feeNQT", "100000000");
        initNxt(properties);
        initBlockchainTest();
    }

    @Before
    public void beforeTest() throws Exception {
        String assetId = issueAsset(BOB, 10000);
        byte[] configBytes = readAllBytes(RUNNER_CONFIG_FILE);
        configJo = JO.parse(new InputStreamReader(new ByteArrayInputStream(configBytes)));
        paramsJo = configJo.getJo("params").getJo("AssetsErc20");
        paramsJo.put("assetId", assetId);
        paramsJo.put("ethereumBlockedAccountSecret", "EBA 7e020dfa 3");
        paramsJo.put("ethereumDeployAccountSecret", "Deployer Address testing");
        paramsJo.put("ethereumDepositAccountsSecret", "ceb3a9f8a009973432c54c5f73be743297e020dfac903908c3f448347a9dbb58");
        setRunnerConfig(configJo.toJSONString().getBytes());
        web3j = Web3j.build(new HttpService(paramsJo.getString("apiUrl")));

        Logger.logInfoMessage("TESTING | beforeTest | assetId: "+ assetId);
        Logger.logInfoMessage("TESTING | beforeTest | paramsJo.assetId: "+ paramsJo.getString("assetId"));

        ethBlockedAcc = AssetsErc20.getCredentialsFromSecret(paramsJo.getString("ethereumBlockedAccountSecret"));
        ethDeployAcc = AssetsErc20.getCredentialsFromSecret(paramsJo.getString("ethereumDeployAccountSecret"));

        Logger.logInfoMessage("EBA=" + ethBlockedAcc.getAddress());
        Logger.logInfoMessage("DEPLOY=" + ethDeployAcc.getAddress());

        ContractTestHelper.deployContract(AssetsErc20.class);
    }

    @After
    public void afterTest() {
        // Revert to the default config
        setRunnerConfig(readAllBytes(RUNNER_CONFIG_FILE));
        ((ContractRunner) AddOns.getAddOn(ContractRunner.class)).reset();
        TestApiAddOn.reset();
    }

    @NotNull
    RetryingRawTransactionManager createTransactionManager(Credentials account) {
        return RetryingRawTransactionManager.create(web3j,
                account, paramsJo.getLong("chainId"), 3, 5000, false,
                (failedPrice) -> failedPrice.multiply(BigInteger.valueOf(2)));
    }

    protected static TriggerContractByRequestCall contractRequest(String command) {
        return TriggerContractByRequestCall.create().contractName("AssetsErc20")
                .setParamValidation(false)
                .param("command", command);
    }

    /**
     * Returns the address for unwrapping dedicated to the tester. This address is under the control of the peg contract
     *
     * @param tester Tester for which the address is returned
     * @return Ethereum address
     */
    protected static String getWrapDepositAddress(Tester tester) {
        JO result = contractRequest("mbGetWrapDepositAddress")
                .param("ardorRecipientPublicKey", tester.getPublicKeyStr()).callNoError();
        Logger.logInfoMessage("response ethDepositAddress: " + result.toJSONString());
        return (String) result.get("depositAddress");
    }

    private String issueAsset(Tester assetIssuer, int quantity) {
        JO issueResult = IssueAssetCall.create(IGNIS.getId())
                .privateKey(assetIssuer.getPrivateKey())
                .feeNQT(20 * IGNIS.ONE_COIN).name("testA").description("Test A")
                .quantityQNT(quantity).decimals(8).callNoError();
        generateBlock();
        return Tester.responseToStringId(issueResult);
    }

    protected static int processWraps(Tester tester) {
        JO result = contractRequest("mbProcessWrapsForAccount")
                .param("ardorRecipientPublicKey", tester.getPublicKeyStr()).callNoError();
        Logger.logInfoMessage("----------------------------------");
        Logger.logInfoMessage("processWraps " + result.toJSONString());
        Logger.logInfoMessage("----------------------------------");
        return result.getInt("starts", 0);
        //Assert.assertEquals(expectedStarts, result.getInt("starts", 0));
        //Assert.assertEquals(expectedAlreadyPending, result.getInt("skippedAlreadyPending", 0));
        //Assert.assertEquals(expectedCompleted, result.getInt("skippedCompleted", 0));
    }

    protected static List<String> waitForUnconfirmedAssetTransfers(Tester account, int count) throws InterruptedException {
        while (true) {
            JO jo = GetUnconfirmedTransactionsCall.create(IGNIS.getId()).account(account.getId()).callNoError();
            JA unconfirmedTransactions = jo.getArray("unconfirmedTransactions");
            if (unconfirmedTransactions.stream().filter(t ->
                    ((JO) t).getInt("type") == 2 && ((JO) t).getInt("subtype") == 1).count() >= count) {
                Assert.assertEquals(count, unconfirmedTransactions.size());
                return ((Stream<JO>) unconfirmedTransactions.stream()).map(t -> t.getString("fullHash")).collect(Collectors.toList());
            }
            Thread.sleep(300);
        }
    }

    protected void confirmArdorTransactions(List<String> fullHashes) throws InterruptedException {
        Logger.logInfoMessage("confirmArdorTransactions:" + fullHashes);

        Thread.sleep(AssetsErc20.UNCONFIRMED_TX_RETRY_MILLIS + 1000);

        int confirmations = paramsJo.getInt("ardorConfirmations") + 1;
        generateBlocks(confirmations);

        fullHashes.forEach(fullHash -> {
            Assert.assertEquals(confirmations, GetTransactionCall.create().fullHash(fullHash).callNoError().getInt("confirmations"));
        });

        Thread.sleep(AssetsErc20.ARDOR_BLOCK_TIME * confirmations * 1000L + 2000);
    }
}
