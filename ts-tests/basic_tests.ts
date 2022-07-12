import { expect } from 'chai';
import { describe, it, before, afterEach } from 'mocha';
import SpeculosTransport from '@ledgerhq/hw-transport-node-speculos';
import Axios from 'axios';
import Transport from "./common";
import Kda from "hw-app-kda";
import * as fs from 'fs';
import * as blake2b from "blake2b";
// import libsodium from "libsodium-wrappers";

// await libsodium.ready;
import { instantiate, Nacl } from "js-nacl";


let nacl : Nacl =null;

let ignoredScreens = [ "W e l c o m e", "Cancel", "Working...", "Exit", "Kadena 0.1.1", "Back", "Settings", "Enable Hash Signing", "Disable Hash Signing"]

let setAcceptAutomationRules = async function() {
    await Axios.post("http://localhost:5000/automation", {
      version: 1,
      rules: [
        ... ignoredScreens.map(txt => { return { "text": txt, "actions": [] } }),
        { "y": 16, "actions": [] },
        { "text": "Confirm", "actions": [ [ "button", 1, true ], [ "button", 2, true ], [ "button", 2, false ], [ "button", 1, false ] ]},
        { "actions": [ [ "button", 2, true ], [ "button", 2, false ] ]}
      ]
    });
}

let processPrompts = function(prompts: [any]) {
  let i = prompts.filter((a : any) => !ignoredScreens.includes(a["text"])).values();
  let {done, value} = i.next();
  let header = "";
  let prompt = "";
  let rv = [];
  while(!done) {
    if(value["y"] == 1) {
      if(value["text"] != header) {
        if(header || prompt) rv.push({ header, prompt });
        header = value["text"];
        prompt = "";
      }
    } else if(value["y"] == 16) {
      prompt += value["text"];
    } else {
      if(header || prompt) rv.push({ header, prompt });
      rv.push(value);
      header = "";
      prompt = "";
    }
    ({done, value} = i.next());
  }
  return rv;
}

let sendCommandAndAccept = async function(command : any, prompts : any) {
    await setAcceptAutomationRules();
    await Axios.delete("http://localhost:5000/events");

    let transport = await Transport.open("http://localhost:5000/apdu");
    let kda = new Kda(transport);
    
    //await new Promise(resolve => setTimeout(resolve, 100));

    let err = null;
    
    try { await command(kda); } catch(e) {
      err = e;
    }
    
    //await new Promise(resolve => setTimeout(resolve, 100));


    // expect(((await Axios.get("http://localhost:5000/events")).data["events"] as [any]).filter((a : any) => !ignoredScreens.includes(a["text"]))).to.deep.equal(prompts);
    expect(processPrompts((await Axios.get("http://localhost:5000/events")).data["events"] as [any])).to.deep.equal(prompts);

    if(err) throw(err);
}

let sendCommandExpectFail = async function(command : any) {
  await setAcceptAutomationRules();
  await Axios.delete("http://localhost:5000/events");

  let transport = await Transport.open("http://localhost:5000/apdu");
  let kda = new Kda(transport);
  try { await command(kda); } catch(e) {
    return;
  }
  expect.fail("Test should have failed");
}

instantiate(n => { nacl=n; });
describe('basic tests', async function() {

  before( async function() {
    while(!nacl) await new Promise(r => setTimeout(r, 100));
    let transport = await Transport.open("http://localhost:5000/apdu");
    let version_string = (await transport.send(0,0xfe,0,0,Buffer.alloc(0))).slice(0,-2).toString();
    ignoredScreens.push(version_string);
  })

  afterEach( async function() {
    console.log("Clearing settings");
    await Axios.post("http://localhost:5000/automation", {version: 1, rules: []});
    await Axios.delete("http://localhost:5000/events");
  });

  it('provides a public key', async () => {

    await sendCommandAndAccept(async (kda : Kda) => {
      console.log("Started pubkey get");
      let rv = await kda.getPublicKey("44'/626'/0");
      console.log("Reached Pubkey Got");
      expect(rv.publicKey).to.equal("3f6f820616c6d999667deca91a0eccf25f62e2c910a4e77e811241445db888d7");
      return;
    }, [
      { "header": "Provide Public Key",
        "prompt": "3f6f820616c6d999667deca91a0eccf25f62e2c910a4e77e811241445db888d7"
      },
      {
        "text": "Confirm",
        "x": 43,
        "y": 11,
      }
    ]);
  });
  
  it('provides a public key', async () => {
  await sendCommandAndAccept(async (kda : Kda) => {
      console.log("Started pubkey get");
      let rv = await kda.getPublicKey("44'/626'/1");
      console.log("Reached Pubkey Got");
      expect(rv.publicKey).to.equal("10f26b7f3a51d6b9ebbff3a58a5b79fcdef154cbb1fb865af2ee55089a2a1d4f");
      return;
    }, [
        {
          "header": "Provide Public Key",
          "prompt": "10f26b7f3a51d6b9ebbff3a58a5b79fcdef154cbb1fb865af2ee55089a2a1d4f"
        },
        {
          "text": "Confirm",
          "x": 43,
          "y": 11
        }
    ]);
  });

  /*
  it.skip('runs a test', async () => { 
    
    await setAcceptAutomationRules();
    await Axios.delete("http://localhost:5000/events");

    let transport = await Transport.open("http://localhost:5000/apdu");
    let kda = new Kda(transport);
    
    let rv = await kda.getPublicKey("0/0");
   
    await Axios.post("http://localhost:5000/automation", {version: 1, rules: []});

    expect(((await Axios.get("http://localhost:5000/events")).data["events"] as [any]).filter((a : any) => a["text"] != "W e l c o m e")).to.deep.equal([
        {
          "text": "Provide Public Key",
          "x": 16,
          "y": 11
        },
        {
          "text": "pkh-929B536E11497F4EF573A22680528E1785AEA757D9D3C29A5D4CDCBA9E2BF",
          "x": -50,
          "y": 11
        },
        {
          "text": "Confirm",
          "x": 43,
          "y": 11
        }
    ]);
    expect(rv.publicKey).to.equal("04e96341109fdba54691303553ee95b371d9745410f1090055fb7c0aa9e564445483f78cb81526e27ab7869fcd996eb8bd39add229b41f9e30bccccdc00a9d6c4c");
    await Axios.delete("http://localhost:5000/events");
  });
 */
});


function testTransaction(path: string, txn: string, prompts: any[]) {
     return async () => {
       await sendCommandAndAccept(
         async (kda : Kda) => {
           let pubkey = (await kda.getPublicKey(path)).publicKey;
           await Axios.delete("http://localhost:5000/events");

           let rv = await kda.signTransaction(path, Buffer.from(txn, "utf-8").toString("hex"));
           expect(rv.signature.length).to.equal(128);
           let hash = blake2b(32).update(Buffer.from(txn, "utf-8")).digest();
           let pass = nacl.crypto_sign_verify_detached(Buffer.from(rv.signature, 'hex'), hash, Buffer.from(pubkey, 'hex'));
           expect(pass).to.equal(true);
         }, prompts);
     }
}

describe("Signing tests", function() {

  it("can sign a simple transfer",
     testTransaction(
       "0/0",
       '{"networkId":"mainnet01","payload":{"exec":{"data":{},"code":"(coin.transfer \\"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790\\" \\"9790d119589a26114e1a42d92598b3f632551c566819ec48e0e8c54dae6ebb42\\" 11.0)"}},"signers":[{"pubKey":"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790","clist":[{"args":[],"name":"coin.GAS"},{"args":["83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790","9790d119589a26114e1a42d92598b3f632551c566819ec48e0e8c54dae6ebb42",11],"name":"coin.TRANSFER"}]}],"meta":{"creationTime":1634009214,"ttl":28800,"gasLimit":600,"chainId":"0","gasPrice":1.0e-5,"sender":"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790"},"nonce":"\\"2021-10-12T03:27:53.700Z\\""}',
       [
         { "header": "Signing", "prompt": "Transaction" },
         { "header": "On Network", "prompt": "mainnet01" },
         { "header": "Requiring", "prompt": "Capabilities" },
         { "header": "Of Key", "prompt": "83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790" },
         { "header": "Paying Gas", "prompt": " " },
         { "header": "Transfer 1", "prompt": "11 from \"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790\" to \"9790d119589a26114e1a42d92598b3f632551c566819ec48e0e8c54dae6ebb42\"" },
         { "header": "On Chain", "prompt": "0" },
         { "header": "Using Gas", "prompt": "at most 600 at price 1.0e-5" },
         { "header": "Transaction hash", "prompt": "fPSCfMUaoK1N31qwhwBFUPwG-YR_guPP894uixsNZgk" },
         { "header": "Sign for Address", "prompt": "ffd8cd79deb956fa3c7d9be0f836f20ac84b140168a087a842be4760e40e2b1c" },
         {
           "text": "Sign Transaction?",
           "x": 19,
           "y": 11,
         },
         {
           "text": "Confirm",
           "x": 43,
           "y": 11,
         }
       ]
     ));
     it("can sign a different simple transfer",
        testTransaction(
          "0/0",
          '{"networkId":"mainnet01","payload":{"exec":{"data":{},"code":"(coin.transfer \\"aab7d3e457f3f78480832d6ac4ace7387f460620a63a5b68c8c799d6bff1566a\\" \\"4c310df6224d674d80463a29cde00cb0ecfb71e0cfdce494243a61b8ea572dfd\\" 2.0)"}},"signers":[{"pubKey":"aab7d3e457f3f78480832d6ac4ace7387f460620a63a5b68c8c799d6bff1566a","clist":[{"args":["aab7d3e457f3f78480832d6ac4ace7387f460620a63a5b68c8c799d6bff1566a","4c310df6224d674d80463a29cde00cb0ecfb71e0cfdce494243a61b8ea572dfd",2],"name":"coin.TRANSFER"},{"args":[],"name":"coin.GAS"}]}],"meta":{"creationTime":1634009195,"ttl":900,"gasLimit":600,"chainId":"0","gasPrice":1.0e-6,"sender":"aab7d3e457f3f78480832d6ac4ace7387f460620a63a5b68c8c799d6bff1566a"},"nonce":"\\"2021-10-12T03:27:35.231Z\\""}',
          [
            { "header": "Signing", "prompt": "Transaction" },
            { "header": "On Network", "prompt": "mainnet01" },
            { "header": "Requiring", "prompt": "Capabilities" },
            { "header": "Of Key", "prompt": "aab7d3e457f3f78480832d6ac4ace7387f460620a63a5b68c8c799d6bff1566a" },
            {
              "header": "Transfer 1",
              "prompt": "2 from \"aab7d3e457f3f78480832d6ac4ace7387f460620a63a5b68c8c799d6bff1566a\" to \"4c310df6224d674d80463a29cde00cb0ecfb71e0cfdce494243a61b8ea572dfd\"",
            },
            {
              "header": "Paying Gas",
              "prompt": " ",
            },
            { "header": "On Chain", "prompt": "0" },
            { "header": "Using Gas", "prompt": "at most 600 at price 1.0e-6" },
            {
              "header": "Transaction hash",
              "prompt": "zPntpx9VQ7vumUoWSvvi8s_h8L1s6GOOLu8-Jgjh9dE",
            },
            {
              "header": "Sign for Address",
              "prompt": "ffd8cd79deb956fa3c7d9be0f836f20ac84b140168a087a842be4760e40e2b1c",
            },
            {
              "text": "Sign Transaction?",
              "x": 19,
              "y": 11,
            },
            {
              "text": "Confirm",
              "x": 43,
              "y": 11,
            }
          ]));
     it("can sign a simple transfer with decimal amount",
        testTransaction(
          "0/0",
          '{"networkId":"mainnet01","payload":{"exec":{"data":{},"code":"(coin.transfer \\"aab7d3e457f3f78480832d6ac4ace7387f460620a63a5b68c8c799d6bff1566a\\" \\"4c310df6224d674d80463a29cde00cb0ecfb71e0cfdce494243a61b8ea572dfd\\" 2.0)"}},"signers":[{"pubKey":"aab7d3e457f3f78480832d6ac4ace7387f460620a63a5b68c8c799d6bff1566a","clist":[{"args":["aab7d3e457f3f78480832d6ac4ace7387f460620a63a5b68c8c799d6bff1566a","4c310df6224d674d80463a29cde00cb0ecfb71e0cfdce494243a61b8ea572dfd",{"decimal":"123456789.0123456789"}],"name":"coin.TRANSFER"},{"args":[],"name":"coin.GAS"}]}],"meta":{"creationTime":1634009195,"ttl":900,"gasLimit":600,"chainId":"0","gasPrice":1.0e-6,"sender":"aab7d3e457f3f78480832d6ac4ace7387f460620a63a5b68c8c799d6bff1566a"},"nonce":"\\"2021-10-12T03:27:35.231Z\\""}',
          [
            { "header": "Signing", "prompt": "Transaction" },
            { "header": "On Network", "prompt": "mainnet01" },
            { "header": "Requiring", "prompt": "Capabilities" },
            { "header": "Of Key", "prompt": "aab7d3e457f3f78480832d6ac4ace7387f460620a63a5b68c8c799d6bff1566a" },
            {
              "header": "Transfer 1",
              "prompt": "{\"decimal\":\"123456789.0123456789\"} from \"aab7d3e457f3f78480832d6ac4ace7387f460620a63a5b68c8c799d6bff1566a\" to \"4c310df6224d674d80463a29cde00cb0ecfb71e0cfdce494243a61b8ea572dfd\"",
            },
            {
              "header": "Paying Gas",
              "prompt": " ",
            },
            { "header": "On Chain", "prompt": "0" },
            { "header": "Using Gas", "prompt": "at most 600 at price 1.0e-6" },
            {
              "header": "Transaction hash",
              "prompt": "u4kRsc0DEmRbOOG2gePtMADMTOGGtRsXrMQ2R4bAvk4",
            },
            {
              "header": "Sign for Address",
              "prompt": "ffd8cd79deb956fa3c7d9be0f836f20ac84b140168a087a842be4760e40e2b1c",
            },
            {
              "text": "Sign Transaction?",
              "x": 19,
              "y": 11,
            },
            {
              "text": "Confirm",
              "x": 43,
              "y": 11,
            }
          ]));
          it("can sign a transfer-create",
             testTransaction(
       "0/0",
       '{"networkId":"mainnet01","payload":{"exec":{"data":{"recp-ks":{"pred":"keys-all","keys":["875e4493e19c8721583bfb46f0768f10266ebcca33c4a0e04bc099a7044a90f7"]}},"code":"(coin.transfer-create \\"e4a1b2980c086c4551ab7d2148cf56e9774c64eb86f795d5fd83e39ccfd2ec66\\" \\"875e4493e19c8721583bfb46f0768f10266ebcca33c4a0e04bc099a7044a90f7\\" (read-keyset \\"recp-ks\\") 4.98340488)"}},"signers":[{"pubKey":"e4a1b2980c086c4551ab7d2148cf56e9774c64eb86f795d5fd83e39ccfd2ec66","clist":[{"args":[],"name":"coin.GAS"},{"args":["e4a1b2980c086c4551ab7d2148cf56e9774c64eb86f795d5fd83e39ccfd2ec66","875e4493e19c8721583bfb46f0768f10266ebcca33c4a0e04bc099a7044a90f7",4.98340488],"name":"coin.TRANSFER"}]}],"meta":{"creationTime":1634009142,"ttl":28800,"gasLimit":60000,"chainId":"0","gasPrice":1.0e-6,"sender":"e4a1b2980c086c4551ab7d2148cf56e9774c64eb86f795d5fd83e39ccfd2ec66"},"nonce":"\\"1634009156943\\""}',
       [
         { "header": "Signing", "prompt": "Transaction" },
         { "header": "On Network", "prompt": "mainnet01" },
         { "header": "Requiring", "prompt": "Capabilities" },
         { "header": "Of Key", "prompt": "e4a1b2980c086c4551ab7d2148cf56e9774c64eb86f795d5fd83e39ccfd2ec66" },
         {
           "header": "Paying Gas",
           "prompt": " ",
         },
         {
           "header": "Transfer 1",
           "prompt": "4.98340488 from \"e4a1b2980c086c4551ab7d2148cf56e9774c64eb86f795d5fd83e39ccfd2ec66\" to \"875e4493e19c8721583bfb46f0768f10266ebcca33c4a0e04bc099a7044a90f7\"",
         },
         { "header": "On Chain", "prompt": "0" },
         { "header": "Using Gas", "prompt": "at most 60000 at price 1.0e-6" },
         {
           "header": "Transaction hash",
           "prompt": "SrjHkjfzLHLiOS-5_lcZvLOhiU42NynfAfezMzbeXsw",
         },
         {
           "header": "Sign for Address",
           "prompt": "ffd8cd79deb956fa3c7d9be0f836f20ac84b140168a087a842be4760e40e2b1c",
         },
         {
           "text": "Sign Transaction?",
           "x": 19,
           "y": 11,
         },
         {
           "text": "Confirm",
           "x": 43,
           "y": 11,
         }
       ]));
  it("can sign a second transfer-create",
     testTransaction(
       "0/0",
       '{"networkId":"mainnet01","payload":{"exec":{"data":{"recp-ks":{"pred":"keys-all","keys":["875e4493e19c8721583bfb46f0768f10266ebcca33c4a0e04bc099a7044a90f7"]}},"code":"(coin.transfer-create \\"73580ffb3e5ca9859442395d4c1cb0bf3aa4e7246564ce943b7ae508b3ee7c03\\" \\"875e4493e19c8721583bfb46f0768f10266ebcca33c4a0e04bc099a7044a90f7\\" (read-keyset \\"recp-ks\\") 4.89093455)"}},"signers":[{"pubKey":"73580ffb3e5ca9859442395d4c1cb0bf3aa4e7246564ce943b7ae508b3ee7c03","clist":[{"args":[],"name":"coin.GAS"},{"args":["73580ffb3e5ca9859442395d4c1cb0bf3aa4e7246564ce943b7ae508b3ee7c03","875e4493e19c8721583bfb46f0768f10266ebcca33c4a0e04bc099a7044a90f7",4.89093455],"name":"coin.TRANSFER"}]}],"meta":{"creationTime":1634009098,"ttl":28800,"gasLimit":60000,"chainId":"0","gasPrice":1.0e-6,"sender":"73580ffb3e5ca9859442395d4c1cb0bf3aa4e7246564ce943b7ae508b3ee7c03"},"nonce":"\\"1634009113073\\""}',
       [
         { "header": "Signing",
           "prompt": "Transaction"
         },
         { "header": "On Network", "prompt": "mainnet01" },
         {
           "header": "Requiring",
           "prompt": "Capabilities",
         },
         {
           "header": "Of Key",
           "prompt": "73580ffb3e5ca9859442395d4c1cb0bf3aa4e7246564ce943b7ae508b3ee7c03"
         },
         {
           "header": "Paying Gas",
           "prompt": " ",
         },
         {
           "header": "Transfer 1",
           "prompt": "4.89093455 from \"73580ffb3e5ca9859442395d4c1cb0bf3aa4e7246564ce943b7ae508b3ee7c03\" to \"875e4493e19c8721583bfb46f0768f10266ebcca33c4a0e04bc099a7044a90f7\"",
         },
         { "header": "On Chain", "prompt": "0" },
         { "header": "Using Gas", "prompt": "at most 60000 at price 1.0e-6" },
         {
           "header": "Transaction hash",
           "prompt": "pJsk0-vgbqfzOBFc4zHtFMSMa0aCZpXBZ_QQFxox1-k",
         },
         {
           "header": "Sign for Address",
           "prompt": "ffd8cd79deb956fa3c7d9be0f836f20ac84b140168a087a842be4760e40e2b1c",
         },
         {
           "text": "Sign Transaction?",
           "x": 19,
           "y": 11,
         },
         {
           "text": "Confirm",
           "x": 43,
           "y": 11,
         },
       ]));

  it("can sign a rotate transaction",
     testTransaction(
       "0/0",
'{"networkId":"mainnet01","payload":{"exec":{"data":{"ks":{"pred":"keys-all","keys":["d3300d284f4bcfbc91555184ef026a356e57ff0fa97b5e6c9830750892cd3093"]}},"code":"(coin.rotate \\"d3300d284f4bcfbc91555184ef026a356e57ff0fa97b5e6c9830750892cd3093\\" (read-keyset \\"ks\\"))"}},"signers":[{"pubKey":"81b4511b257fb975dace13e823c257c17ac6a695da65f91b6036d6e1429268fc","clist":[{"args":[],"name":"coin.GAS"},{"args":["d3300d284f4bcfbc91555184ef026a356e57ff0fa97b5e6c9830750892cd3093"],"name":"coin.ROTATE"}]}],"meta":{"creationTime":1633466764,"ttl":28800,"gasLimit":1500,"chainId":"0","gasPrice":1.0e-5,"sender":"81b4511b257fb975dace13e823c257c17ac6a695da65f91b6036d6e1429268fc"},"nonce":"\\"1633466764\\""}',
       [
         { "header": "Signing", "prompt": "Transaction" },
         { "header": "On Network", "prompt": "mainnet01" },
         { "header": "Requiring", "prompt": "Capabilities" },
         { "header": "Of Key", "prompt": "81b4511b257fb975dace13e823c257c17ac6a695da65f91b6036d6e1429268fc" },
         {
           "header": "Paying Gas",
           "prompt": " ",
         },
         {
           "header": "Rotate for account",
           "prompt": "\"d3300d284f4bcfbc91555184ef026a356e57ff0fa97b5e6c9830750892cd3093\"",
         },
         { "header": "On Chain", "prompt": "0" },
         { "header": "Using Gas", "prompt": "at most 1500 at price 1.0e-5" },
         {
           "header": "Transaction hash",
           "prompt": "WQImvdxCaI7U5Qy2U_3Mxoa3i-Lp-PyNu9aZNtXclHo",
         },
         {
           "header": "Sign for Address",
           "prompt": "ffd8cd79deb956fa3c7d9be0f836f20ac84b140168a087a842be4760e40e2b1c",
         },
         {
           "text": "Sign Transaction?",
           "x": 19,
           "y": 11,
         },
         {
           "text": "Confirm",
           "x": 43,
           "y": 11,
         },
       ]));

  it("Shows warning when no capabilities are set for a transaction.",
          testTransaction(
            "44'/626'/0'", "{\"networkId\":\"testnet04\",\"payload\":{\"exec\":{\"data\":{\"ks\":{\"keys\":[\"ffd8cd79deb956fa3c7d9be0f836f20ac84b140168a087a842be4760e40e2b1c\"],\"pred\":\"keys-all\"}},\"code\":\"(not-coin.transfer-crosschain \\\"ffd8cd79deb956fa3c7d9be0f836f20ac84b140168a087a842be4760e40e2b1c\\\" \\\"ffd8cd79deb956fa3c7d9be0f836f20ac84b140168a087a842be4760e40e2b1c\\\" (read-keyset \\\"ks\\\") \\\"0\\\" 1.0)\"}},\"signers\":[{\"pubKey\":\"ffd8cd79deb956fa3c7d9be0f836f20ac84b140168a087a842be4760e40e2b1c\"}],\"meta\":{\"creationTime\":1640290267,\"ttl\":28800,\"gasLimit\":600,\"chainId\":\"1\",\"gasPrice\":0.00001,\"sender\":\"ffd8cd79deb956fa3c7d9be0f836f20ac84b140168a087a842be4760e40e2b1c\"},\"nonce\":\"\\\"\\\\\\\"2021-12-23T20:12:06.664Z\\\\\\\"\\\"\"}",
            [
              {
                "header": "Signing",
                "prompt": "Transaction",
              },
              { "header": "On Network", "prompt": "testnet04" },
              {
                "header": "Requiring",
                "prompt": "Capabilities",
              },
              {
                "header": "Of Key",
                "prompt": "ffd8cd79deb956fa3c7d9be0f836f20ac84b140168a087a842be4760e40e2b1c",
              },
              { "header": "On Chain", "prompt": "1" },
              { "header": "Using Gas", "prompt": "at most 600 at price 0.00001" },
              {
                "header": "WARNING",
                "prompt": "UNSAFE TRANSACTION. This transaction's code was not recognized and does not limit capabilities for all signers. Signing this transaction may make arbitrary actions on the chain including loss of all funds.",
              },
              {
                "header": "Transaction hash",
                "prompt": "EsF-vcYfXYn8-NpYIvBcOMYCfUxiV6wxECU5FWNFz5g",
              },
              {
                "header": "Sign for Address",
                "prompt": "8d5d63bb1071a8dfc5c09ac96cfa50341a74eb91b6ea9ee5724cde09ef758bf2",
              },
              {
                "text": "Sign Transaction?",
                "x": 19,
                "y": 11,
              },
              {
                "text": "Confirm",
                "x": 43,
                "y": 11,
              }
            ]
          ));
  it("Can sign for accounts using k: account names.",
          testTransaction( "44'/626'/0'",
            "{\"networkId\":\"testnet04\",\"payload\":{\"exec\":{\"data\":{\"ks\":{\"keys\":[\"dfdb3896919544490637c0fd2f34f8bf4463d416fbd915990c8a136b1a970ca5\"],\"pred\":\"keys-all\"}},\"code\":\"(coin.transfer-create \\\"k:b9ac3ca5559cc6f394ea0e31c11be16efd6c6ff6804b98ce7cee496bcca96164\\\" \\\"k:dfdb3896919544490637c0fd2f34f8bf4463d416fbd915990c8a136b1a970ca5\\\" (read-keyset \\\"ks\\\") 2.0)\"}},\"signers\":[{\"clist\":[{\"name\":\"coin.GAS\",\"args\":[]},{\"name\":\"coin.TRANSFER\",\"args\":[\"k:b9ac3ca5559cc6f394ea0e31c11be16efd6c6ff6804b98ce7cee496bcca96164\",\"k:dfdb3896919544490637c0fd2f34f8bf4463d416fbd915990c8a136b1a970ca5\",2]}],\"pubKey\":\"b9ac3ca5559cc6f394ea0e31c11be16efd6c6ff6804b98ce7cee496bcca96164\"}],\"meta\":{\"creationTime\":1641331220,\"ttl\":28800,\"gasLimit\":600,\"chainId\":\"1\",\"gasPrice\":0.00001,\"sender\":\"k:b9ac3ca5559cc6f394ea0e31c11be16efd6c6ff6804b98ce7cee496bcca96164\"},\"nonce\":\"\\\"\\\\\\\"2022-01-04T21:21:20.440Z\\\\\\\"\\\"\"}",
            [
              {
                "header": "Signing",
                "prompt": "Transaction",
              },
              { "header": "On Network", "prompt": "testnet04" },
              {
                "header": "Requiring",
                "prompt": "Capabilities",
              },
              {
                "header": "Paying Gas",
                "prompt": " ",
              },
              {
                "header": "Transfer 1",
                "prompt": "2 from \"k:b9ac3ca5559cc6f394ea0e31c11be16efd6c6ff6804b98ce7cee496bcca96164\" to \"k:dfdb3896919544490637c0fd2f34f8bf4463d416fbd915990c8a136b1a970ca5\"",
              },
              {
                "header": "Of Key",
                "prompt": "b9ac3ca5559cc6f394ea0e31c11be16efd6c6ff6804b98ce7cee496bcca96164",
              },
              { "header": "On Chain", "prompt": "1" },
              { "header": "Using Gas", "prompt": "at most 600 at price 0.00001" },
              {
                "header": "Transaction hash",
                "prompt": "9VlNQ6wmY5UpfOcazQNGpBZDt9Cd_sl_DO0POpiBDvU",
              },
              {
                "header": "Sign for Address",
                "prompt": "8d5d63bb1071a8dfc5c09ac96cfa50341a74eb91b6ea9ee5724cde09ef758bf2",
              },
              {
                "text": "Sign Transaction?",
                "x": 19,
                "y": 11,
              },
              {
                "text": "Confirm",
                "x": 43,
                "y": 11,
              }
            ]
          ));
  it("Shows custom message for basic cross-chain transfers.",
          testTransaction(
            "44'/626'/0'", "{\"networkId\":\"testnet04\",\"payload\":{\"exec\":{\"data\":{\"ks\":{\"keys\":[\"ffd8cd79deb956fa3c7d9be0f836f20ac84b140168a087a842be4760e40e2b1c\"],\"pred\":\"keys-all\"}},\"code\":\"(coin.transfer-crosschain \\\"ffd8cd79deb956fa3c7d9be0f836f20ac84b140168a087a842be4760e40e2b1c\\\" \\\"ffd8cd79deb956fa3c7d9be0f836f20ac84b140168a087a842be4760e40e2b1c\\\" (read-keyset \\\"ks\\\") \\\"0\\\" 1.0)\"}},\"signers\":[{\"pubKey\":\"ffd8cd79deb956fa3c7d9be0f836f20ac84b140168a087a842be4760e40e2b1c\",\"clist\":[{\"name\":\"coin.GAS\",\"args\":[]},{\"name\":\"coin.TRANSFER_XCHAIN\",\"args\":[\"k:ffd8cd79deb956fa3c7d9be0f836f20ac84b140168a087a842be4760e40e2b1c\",\"k:ffd8cd79deb956fa3c7d9be0f836f20ac84b140168a087a842be4760e40e2b1c\",1.0,\"0\"]}]}],\"meta\":{\"creationTime\":1640290267,\"ttl\":28800,\"gasLimit\":600,\"chainId\":\"1\",\"gasPrice\":0.00001,\"sender\":\"ffd8cd79deb956fa3c7d9be0f836f20ac84b140168a087a842be4760e40e2b1c\"},\"nonce\":\"\\\"\\\\\\\"2021-12-23T20:12:06.664Z\\\\\\\"\\\"\"}",
            [
              {
                "header": "Signing",
                "prompt": "Transaction",
              },
              { "header": "On Network", "prompt": "testnet04" },
              {
                "header": "Requiring",
                "prompt": "Capabilities",
              },
              {
                "header": "Of Key",
                "prompt": "ffd8cd79deb956fa3c7d9be0f836f20ac84b140168a087a842be4760e40e2b1c",
              },
              {
                "header": "Paying Gas",
                "prompt": " ",
              },
              {
                "header": "Transfer 1",
                "prompt": "Cross-chain 1.0 from \"k:ffd8cd79deb956fa3c7d9be0f836f20ac84b140168a087a842be4760e40e2b1c\" to \"k:ffd8cd79deb956fa3c7d9be0f836f20ac84b140168a087a842be4760e40e2b1c\" to chain \"0\"",
              },
              { "header": "On Chain", "prompt": "1" },
              { "header": "Using Gas", "prompt": "at most 600 at price 0.00001" },
              {
                "header": "Transaction hash",
                "prompt": "nw3YtHZ5EgogG2oQ9JbOOEqyhy7IN4cevGjdEKuWgQM",
              },
              {
                "header": "Sign for Address",
                "prompt": "8d5d63bb1071a8dfc5c09ac96cfa50341a74eb91b6ea9ee5724cde09ef758bf2",
              },
              {
                "text": "Sign Transaction?",
                "x": 19,
                "y": 11,
              },
              {
                "text": "Confirm",
                "x": 43,
                "y": 11,
              }
            ]
          ));
  it("Shows custom message for basic cross-chain transfers with decimal amount.",
          testTransaction(
            "44'/626'/0'", "{\"networkId\":\"testnet04\",\"payload\":{\"exec\":{\"data\":{\"ks\":{\"keys\":[\"ffd8cd79deb956fa3c7d9be0f836f20ac84b140168a087a842be4760e40e2b1c\"],\"pred\":\"keys-all\"}},\"code\":\"(coin.transfer-crosschain \\\"ffd8cd79deb956fa3c7d9be0f836f20ac84b140168a087a842be4760e40e2b1c\\\" \\\"ffd8cd79deb956fa3c7d9be0f836f20ac84b140168a087a842be4760e40e2b1c\\\" (read-keyset \\\"ks\\\") \\\"0\\\" 1.0)\"}},\"signers\":[{\"pubKey\":\"ffd8cd79deb956fa3c7d9be0f836f20ac84b140168a087a842be4760e40e2b1c\",\"clist\":[{\"name\":\"coin.GAS\",\"args\":[]},{\"name\":\"coin.TRANSFER_XCHAIN\",\"args\":[\"k:ffd8cd79deb956fa3c7d9be0f836f20ac84b140168a087a842be4760e40e2b1c\",\"k:ffd8cd79deb956fa3c7d9be0f836f20ac84b140168a087a842be4760e40e2b1c\",{\"decimal\":\"123456789.0123456789\"},\"0\"]}]}],\"meta\":{\"creationTime\":1640290267,\"ttl\":28800,\"gasLimit\":600,\"chainId\":\"1\",\"gasPrice\":0.00001,\"sender\":\"ffd8cd79deb956fa3c7d9be0f836f20ac84b140168a087a842be4760e40e2b1c\"},\"nonce\":\"\\\"\\\\\\\"2021-12-23T20:12:06.664Z\\\\\\\"\\\"\"}",
            [
              {
                "header": "Signing",
                "prompt": "Transaction",
              },
              { "header": "On Network", "prompt": "testnet04" },
              {
                "header": "Requiring",
                "prompt": "Capabilities",
              },
              {
                "header": "Of Key",
                "prompt": "ffd8cd79deb956fa3c7d9be0f836f20ac84b140168a087a842be4760e40e2b1c",
              },
              {
                "header": "Paying Gas",
                "prompt": " ",
              },
              {
                "header": "Transfer 1",
                "prompt": "Cross-chain {\"decimal\":\"123456789.0123456789\"} from \"k:ffd8cd79deb956fa3c7d9be0f836f20ac84b140168a087a842be4760e40e2b1c\" to \"k:ffd8cd79deb956fa3c7d9be0f836f20ac84b140168a087a842be4760e40e2b1c\" to chain \"0\"",
              },
              { "header": "On Chain", "prompt": "1" },
              { "header": "Using Gas", "prompt": "at most 600 at price 0.00001" },
              {
                "header": "Transaction hash",
                "prompt": "gaYu1-LR6N9V0bUt1u_N9p4cbm_dwy7IeHC52rD92gs",
              },
              {
                "header": "Sign for Address",
                "prompt": "8d5d63bb1071a8dfc5c09ac96cfa50341a74eb91b6ea9ee5724cde09ef758bf2",
              },
              {
                "text": "Sign Transaction?",
                "x": 19,
                "y": 11,
              },
              {
                "text": "Confirm",
                "x": 43,
                "y": 11,
              }
            ]
          ));
     it("can sign a multiple transfers",
        testTransaction(
          "0/0",
          '{"networkId":"mainnet01","payload":{"exec":{"data":{},"code":"(coin.transfer \\"aab7d3e457f3f78480832d6ac4ace7387f460620a63a5b68c8c799d6bff1566a\\" \\"4c310df6224d674d80463a29cde00cb0ecfb71e0cfdce494243a61b8ea572dfd\\" 2.0)"}},"signers":[{"pubKey":"aab7d3e457f3f78480832d6ac4ace7387f460620a63a5b68c8c799d6bff1566a","clist":[{"args":["aab7d3e457f3f78480832d6ac4ace7387f460620a63a5b68c8c799d6bff1566a","4c310df6224d674d80463a29cde00cb0ecfb71e0cfdce494243a61b8ea572dfa",1],"name":"coin.TRANSFER"},{"args":["aab7d3e457f3f78480832d6ac4ace7387f460620a63a5b68c8c799d6bff1566a","4c310df6224d674d80463a29cde00cb0ecfb71e0cfdce494243a61b8ea572dfb",2],"name":"coin.TRANSFER"},{"args":["aab7d3e457f3f78480832d6ac4ace7387f460620a63a5b68c8c799d6bff1566a","4c310df6224d674d80463a29cde00cb0ecfb71e0cfdce494243a61b8ea572dfc",3],"name":"coin.TRANSFER"},{"args":["aab7d3e457f3f78480832d6ac4ace7387f460620a63a5b68c8c799d6bff1566a","4c310df6224d674d80463a29cde00cb0ecfb71e0cfdce494243a61b8ea572dfd",4],"name":"coin.TRANSFER"},{"args":[],"name":"coin.GAS"}]}],"meta":{"creationTime":1634009195,"ttl":900,"gasLimit":600,"chainId":"0","gasPrice":1.0e-6,"sender":"aab7d3e457f3f78480832d6ac4ace7387f460620a63a5b68c8c799d6bff1566a"},"nonce":"\\"2021-10-12T03:27:35.231Z\\""}',
          [
            { "header": "Signing", "prompt": "Transaction" },
            { "header": "On Network", "prompt": "mainnet01" },
            { "header": "Requiring", "prompt": "Capabilities" },
            { "header": "Of Key", "prompt": "aab7d3e457f3f78480832d6ac4ace7387f460620a63a5b68c8c799d6bff1566a" },
            {
              "header": "Transfer 1",
              "prompt": "1 from \"aab7d3e457f3f78480832d6ac4ace7387f460620a63a5b68c8c799d6bff1566a\" to \"4c310df6224d674d80463a29cde00cb0ecfb71e0cfdce494243a61b8ea572dfa\"",
            },
            {
              "header": "Transfer 2",
              "prompt": "2 from \"aab7d3e457f3f78480832d6ac4ace7387f460620a63a5b68c8c799d6bff1566a\" to \"4c310df6224d674d80463a29cde00cb0ecfb71e0cfdce494243a61b8ea572dfb\"",
            },
            {
              "header": "Transfer 3",
              "prompt": "3 from \"aab7d3e457f3f78480832d6ac4ace7387f460620a63a5b68c8c799d6bff1566a\" to \"4c310df6224d674d80463a29cde00cb0ecfb71e0cfdce494243a61b8ea572dfc\"",
            },
            {
              "header": "Transfer 4",
              "prompt": "4 from \"aab7d3e457f3f78480832d6ac4ace7387f460620a63a5b68c8c799d6bff1566a\" to \"4c310df6224d674d80463a29cde00cb0ecfb71e0cfdce494243a61b8ea572dfd\"",
            },
            {
              "header": "Paying Gas",
              "prompt": " ",
            },
            { "header": "On Chain", "prompt": "0" },
            { "header": "Using Gas", "prompt": "at most 600 at price 1.0e-6" },
            {
              "header": "Transaction hash",
              "prompt": "cYmajadc0EPG3ifvKR1Yd_-wlG79UZirK47JOREfZhk",
            },
            {
              "header": "Sign for Address",
              "prompt": "ffd8cd79deb956fa3c7d9be0f836f20ac84b140168a087a842be4760e40e2b1c",
            },
            {
              "text": "Sign Transaction?",
              "x": 19,
              "y": 11,
            },
            {
              "text": "Confirm",
              "x": 43,
              "y": 11,
            }
          ]));
     it("can sign a multiple transfers, with xchain",
        testTransaction(
          "0/0",
          '{"networkId":"mainnet01","payload":{"exec":{"data":{},"code":"(coin.transfer \\"aab7d3e457f3f78480832d6ac4ace7387f460620a63a5b68c8c799d6bff1566a\\" \\"4c310df6224d674d80463a29cde00cb0ecfb71e0cfdce494243a61b8ea572dfd\\" 2.0)"}},"signers":[{"pubKey":"aab7d3e457f3f78480832d6ac4ace7387f460620a63a5b68c8c799d6bff1566a","clist":[{"args":["aab7d3e457f3f78480832d6ac4ace7387f460620a63a5b68c8c799d6bff1566a","4c310df6224d674d80463a29cde00cb0ecfb71e0cfdce494243a61b8ea572dfa",1],"name":"coin.TRANSFER"},{"args":["aab7d3e457f3f78480832d6ac4ace7387f460620a63a5b68c8c799d6bff1566a","4c310df6224d674d80463a29cde00cb0ecfb71e0cfdce494243a61b8ea572dfb",2,"3"],"name":"coin.TRANSFER_XCHAIN"},{"args":["aab7d3e457f3f78480832d6ac4ace7387f460620a63a5b68c8c799d6bff1566a","4c310df6224d674d80463a29cde00cb0ecfb71e0cfdce494243a61b8ea572dfc",3,"2"],"name":"coin.TRANSFER_XCHAIN"},{"args":["aab7d3e457f3f78480832d6ac4ace7387f460620a63a5b68c8c799d6bff1566a","4c310df6224d674d80463a29cde00cb0ecfb71e0cfdce494243a61b8ea572dfd",4],"name":"coin.TRANSFER"},{"args":[],"name":"coin.GAS"}]}],"meta":{"creationTime":1634009195,"ttl":900,"gasLimit":600,"chainId":"0","gasPrice":1.0e-6,"sender":"aab7d3e457f3f78480832d6ac4ace7387f460620a63a5b68c8c799d6bff1566a"},"nonce":"\\"2021-10-12T03:27:35.231Z\\""}',
          [
            { "header": "Signing", "prompt": "Transaction" },
            { "header": "On Network", "prompt": "mainnet01" },
            { "header": "Requiring", "prompt": "Capabilities" },
            { "header": "Of Key", "prompt": "aab7d3e457f3f78480832d6ac4ace7387f460620a63a5b68c8c799d6bff1566a" },
            {
              "header": "Transfer 1",
              "prompt": "1 from \"aab7d3e457f3f78480832d6ac4ace7387f460620a63a5b68c8c799d6bff1566a\" to \"4c310df6224d674d80463a29cde00cb0ecfb71e0cfdce494243a61b8ea572dfa\"",
            },
            {
              "header": "Transfer 2",
              "prompt": "Cross-chain 2 from \"aab7d3e457f3f78480832d6ac4ace7387f460620a63a5b68c8c799d6bff1566a\" to \"4c310df6224d674d80463a29cde00cb0ecfb71e0cfdce494243a61b8ea572dfb\" to chain \"3\"",
            },
            {
              "header": "Transfer 3",
              "prompt": "Cross-chain 3 from \"aab7d3e457f3f78480832d6ac4ace7387f460620a63a5b68c8c799d6bff1566a\" to \"4c310df6224d674d80463a29cde00cb0ecfb71e0cfdce494243a61b8ea572dfc\" to chain \"2\"",
            },
            {
              "header": "Transfer 4",
              "prompt": "4 from \"aab7d3e457f3f78480832d6ac4ace7387f460620a63a5b68c8c799d6bff1566a\" to \"4c310df6224d674d80463a29cde00cb0ecfb71e0cfdce494243a61b8ea572dfd\"",
            },
            {
              "header": "Paying Gas",
              "prompt": " ",
            },
            { "header": "On Chain", "prompt": "0" },
            { "header": "Using Gas", "prompt": "at most 600 at price 1.0e-6" },
            {
              "header": "Transaction hash",
              "prompt": "AoXqSSMScM_u4glsmLV3C8Eawexbm2YEFgFMHYFzm4o",
            },
            {
              "header": "Sign for Address",
              "prompt": "ffd8cd79deb956fa3c7d9be0f836f20ac84b140168a087a842be4760e40e2b1c",
            },
            {
              "text": "Sign Transaction?",
              "x": 19,
              "y": 11,
            },
            {
              "text": "Confirm",
              "x": 43,
              "y": 11,
            }
          ]));
});


function testSignHash(path: string, hash: string, prompts: any[]) {
     return async () => {
       await sendCommandAndAccept(
         async (kda : Kda) => {
           let pubkey = (await kda.getPublicKey(path)).publicKey;
           await toggleHashSettings();
           await Axios.delete("http://localhost:5000/events");
           let rv = await kda.signHash(path, hash);
           expect(rv.signature.length).to.equal(128);
           const rawHash = hash.length == 64 ? Buffer.from(hash, "hex") : Buffer.from(hash, "base64");
           let pass = nacl.crypto_sign_verify_detached(Buffer.from(rv.signature, 'hex'), rawHash, Buffer.from(pubkey, 'hex'));
           expect(pass).to.equal(true);
           // reset setting
           await toggleHashSettings();
         }, prompts);
     }
}

function testSignHashFail(path: string, hash: string) {
  return async () => {
    await sendCommandExpectFail(
      async (kda : Kda) => {
        await kda.signHash(path, hash);
      });
  }
}

function testSignHashFail2(path: string, hash: string) {
  return async () => {
    await sendCommandExpectFail(
      async (kda : Kda) => {
        // Enable and then disable
        await toggleHashSettings();
        await toggleHashSettings();
        await Axios.delete("http://localhost:5000/events");
        await kda.signHash(path, hash);
      });
  }
}

let toggleHashSettings = async function() {
  await Axios.post("http://localhost:5000/button/right", {"action":"press-and-release"});
  await Axios.post("http://localhost:5000/button/right", {"action":"press-and-release"});
  await Axios.post("http://localhost:5000/button/both", {"action":"press-and-release"});
  await Axios.post("http://localhost:5000/button/both", {"action":"press-and-release"});
  await Axios.post("http://localhost:5000/button/right", {"action":"press-and-release"});
  await Axios.post("http://localhost:5000/button/both", {"action":"press-and-release"});
}

describe('Hash Signing Tests', function() {
  it("cannot sign a hash without settings enabled",
     testSignHashFail(
       "0/0",
       'ffd8cd79deb956fa3c7d9be0f836f20ac84b140168a087a842be4760e40e2b1c'
     ));
  it("cannot sign a hash without settings enabled 2",
     testSignHashFail2(
       "0/0",
       'ffd8cd79deb956fa3c7d9be0f836f20ac84b140168a087a842be4760e40e2b1c'
     ));
  it("can sign a hash after enabling settings",
     testSignHash(
       "0/0",
       'ffd8cd79deb956fa3c7d9be0f836f20ac84b140168a087a842be4760e40e2b1c',
       [
         { "header": "Signing", "prompt": "Transaction Hash" },
         { "header": "Transaction hash", "prompt": "_9jNed65Vvo8fZvg-DbyCshLFAFooIeoQr5HYOQOKxw" },
         { "header": "Sign for Address", "prompt": "ffd8cd79deb956fa3c7d9be0f836f20ac84b140168a087a842be4760e40e2b1c" },
         {
           "text": "Sign Transaction Hash?",
           "x": 4,
           "y": 11,
         },
         {
           "text": "Confirm",
           "x": 43,
           "y": 11,
         }
       ]
     ));
  it("can sign a hash after enabling settings with base64 encoding",
     testSignHash(
       "0/0",
       '_9jNed65Vvo8fZvg-DbyCshLFAFooIeoQr5HYOQOKxw',
       [
         { "header": "Signing", "prompt": "Transaction Hash" },
         { "header": "Transaction hash", "prompt": "_9jNed65Vvo8fZvg-DbyCshLFAFooIeoQr5HYOQOKxw" },
         { "header": "Sign for Address", "prompt": "ffd8cd79deb956fa3c7d9be0f836f20ac84b140168a087a842be4760e40e2b1c" },
         {
           "text": "Sign Transaction Hash?",
           "x": 4,
           "y": 11,
         },
         {
           "text": "Confirm",
           "x": 43,
           "y": 11,
         }
       ]
     ));
})

const WARNING_FOR_CAP_NOT_SHOWN = "Transaction too large for Ledger to display.  PROCEED WITH GREAT CAUTION.  Do you want to continue?";

describe("Capability Signing tests", function() {

  it("can sign an arbitrary cap with no args",
     testTransaction(
       "0/0",
       '{"networkId":"mainnet01","payload":{"exec":{"data":{},"code":"(coin.transfer \\"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790\\" \\"9790d119589a26114e1a42d92598b3f632551c566819ec48e0e8c54dae6ebb42\\" 11.0)"}},"signers":[{"pubKey":"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790","clist":[{"args":[],"name":"coin.GAS"},{"args":[],"name":"mycoin.MY_TRANSFER"}]}],"meta":{"creationTime":1634009214,"ttl":28800,"gasLimit":600,"chainId":"0","gasPrice":1.0e-5,"sender":"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790"},"nonce":"\\"2021-10-12T03:27:53.700Z\\""}',
       [
         { "header": "Signing", "prompt": "Transaction" },
         { "header": "On Network", "prompt": "mainnet01" },
         { "header": "Requiring", "prompt": "Capabilities" },
         { "header": "Of Key", "prompt": "83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790" },
         { "header": "Paying Gas", "prompt": " " },
         { "header": "Unknown Capability 1", "prompt": "name: mycoin.MY_TRANSFER, no args" },
         { "header": "On Chain", "prompt": "0" },
         { "header": "Using Gas", "prompt": "at most 600 at price 1.0e-5" },
         { "header": "Transaction hash", "prompt": "hnaoFEVgtSMrwKbm2Ui4wnARtUwMo6rtB3fnvZGb8oE" },
         { "header": "Sign for Address", "prompt": "ffd8cd79deb956fa3c7d9be0f836f20ac84b140168a087a842be4760e40e2b1c" },
         {
           "text": "Sign Transaction?",
           "x": 19,
           "y": 11,
         },
         {
           "text": "Confirm",
           "x": 43,
           "y": 11,
         }
       ]
     ));

  it("can sign an arbitrary cap with single string arg",
     testTransaction(
       "0/0",
       '{"networkId":"mainnet01","payload":{"exec":{"data":{},"code":"(coin.transfer \\"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790\\" \\"9790d119589a26114e1a42d92598b3f632551c566819ec48e0e8c54dae6ebb42\\" 11.0)"}},"signers":[{"pubKey":"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790","clist":[{"args":[],"name":"coin.GAS"},{"args":["83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790"],"name":"mycoin.MY_TRANSFER"}]}],"meta":{"creationTime":1634009214,"ttl":28800,"gasLimit":600,"chainId":"0","gasPrice":1.0e-5,"sender":"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790"},"nonce":"\\"2021-10-12T03:27:53.700Z\\""}',
       [
         { "header": "Signing", "prompt": "Transaction" },
         { "header": "On Network", "prompt": "mainnet01" },
         { "header": "Requiring", "prompt": "Capabilities" },
         { "header": "Of Key", "prompt": "83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790" },
         { "header": "Paying Gas", "prompt": " " },
         { "header": "Unknown Capability 1", "prompt": "name: mycoin.MY_TRANSFER, arg 1: \"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790\"" },
         { "header": "On Chain", "prompt": "0" },
         { "header": "Using Gas", "prompt": "at most 600 at price 1.0e-5" },
         { "header": "Transaction hash", "prompt": "kQqVYwYzDNSKqcRwJ3Yd4xgG2UW9j2sdcupQx-T6XEY" },
         { "header": "Sign for Address", "prompt": "ffd8cd79deb956fa3c7d9be0f836f20ac84b140168a087a842be4760e40e2b1c" },
         {
           "text": "Sign Transaction?",
           "x": 19,
           "y": 11,
         },
         {
           "text": "Confirm",
           "x": 43,
           "y": 11,
         }
       ]
     ));

  it("can sign an arbitrary cap with two string args",
     testTransaction(
       "0/0",
       '{"networkId":"mainnet01","payload":{"exec":{"data":{},"code":"(coin.transfer \\"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790\\" \\"9790d119589a26114e1a42d92598b3f632551c566819ec48e0e8c54dae6ebb42\\" 11.0)"}},"signers":[{"pubKey":"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790","clist":[{"args":[],"name":"coin.GAS"},{"args":["83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790","second arg"],"name":"mycoin.MY_TRANSFER"}]}],"meta":{"creationTime":1634009214,"ttl":28800,"gasLimit":600,"chainId":"0","gasPrice":1.0e-5,"sender":"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790"},"nonce":"\\"2021-10-12T03:27:53.700Z\\""}',
       [
         { "header": "Signing", "prompt": "Transaction" },
         { "header": "On Network", "prompt": "mainnet01" },
         { "header": "Requiring", "prompt": "Capabilities" },
         { "header": "Of Key", "prompt": "83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790" },
         { "header": "Paying Gas", "prompt": " " },
         { "header": "Unknown Capability 1", "prompt": "name: mycoin.MY_TRANSFER, arg 1: \"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790\", arg 2: \"second arg\"" },
         { "header": "On Chain", "prompt": "0" },
         { "header": "Using Gas", "prompt": "at most 600 at price 1.0e-5" },
         { "header": "Transaction hash", "prompt": "ONXn9kz2V9InGB-RddO3kUCy-GHQOEs8jRYqO2vzxuY" },
         { "header": "Sign for Address", "prompt": "ffd8cd79deb956fa3c7d9be0f836f20ac84b140168a087a842be4760e40e2b1c" },
         {
           "text": "Sign Transaction?",
           "x": 19,
           "y": 11,
         },
         {
           "text": "Confirm",
           "x": 43,
           "y": 11,
         }
       ]
     ));

  it("can sign an arbitrary cap with two string args and one number",
     testTransaction(
       "0/0",
       '{"networkId":"mainnet01","payload":{"exec":{"data":{},"code":"(coin.transfer \\"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790\\" \\"9790d119589a26114e1a42d92598b3f632551c566819ec48e0e8c54dae6ebb42\\" 11.0)"}},"signers":[{"pubKey":"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790","clist":[{"args":[],"name":"coin.GAS"},{"args":["83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790","second arg",22.2],"name":"mycoin.MY_TRANSFER"}]}],"meta":{"creationTime":1634009214,"ttl":28800,"gasLimit":600,"chainId":"0","gasPrice":1.0e-5,"sender":"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790"},"nonce":"\\"2021-10-12T03:27:53.700Z\\""}',
       [
         { "header": "Signing", "prompt": "Transaction" },
         { "header": "On Network", "prompt": "mainnet01" },
         { "header": "Requiring", "prompt": "Capabilities" },
         { "header": "Of Key", "prompt": "83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790" },
         { "header": "Paying Gas", "prompt": " " },
         { "header": "Unknown Capability 1", "prompt": "name: mycoin.MY_TRANSFER, arg 1: \"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790\", arg 2: \"second arg\", arg 3: 22.2" },
         { "header": "On Chain", "prompt": "0" },
         { "header": "Using Gas", "prompt": "at most 600 at price 1.0e-5" },
         { "header": "Transaction hash", "prompt": "OEV1W2Adz7vvU3qYzV9V48pDhxRdFDi2KG4JXx73WTA" },
         { "header": "Sign for Address", "prompt": "ffd8cd79deb956fa3c7d9be0f836f20ac84b140168a087a842be4760e40e2b1c" },
         {
           "text": "Sign Transaction?",
           "x": 19,
           "y": 11,
         },
         {
           "text": "Confirm",
           "x": 43,
           "y": 11,
         }
       ]
     ));

  it("can sign an arbitrary cap with various json types",
     testTransaction(
       "0/0",
       '{"networkId":"mainnet01","payload":{"exec":{"data":{},"code":"(coin.transfer \\"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790\\" \\"9790d119589a26114e1a42d92598b3f632551c566819ec48e0e8c54dae6ebb42\\" 11.0)"}},"signers":[{"pubKey":"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790","clist":[{"args":[],"name":"coin.GAS"},{"args":[{"key1":{"key2":"val2"},"key3":-2.46,"key4":{"key5":true,"key6":{"key7":0.01},"key8":["a",false,null,9,10.23,-58.24]}},{},[],false,null],"name":"mycoin.MY_TRANSFER"}]}],"meta":{"creationTime":1634009214,"ttl":28800,"gasLimit":600,"chainId":"0","gasPrice":1.0e-5,"sender":"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790"},"nonce":"\\"2021-10-12T03:27:53.700Z\\""}',
       [
         { "header": "Signing", "prompt": "Transaction" },
         { "header": "On Network", "prompt": "mainnet01" },
         { "header": "Requiring", "prompt": "Capabilities" },
         { "header": "Of Key", "prompt": "83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790" },
         { "header": "Paying Gas", "prompt": " " },
         { "header": "Unknown Capability 1", "prompt": "name: mycoin.MY_TRANSFER, arg 1: {\"key1\":{\"key2\":\"val2\"},\"key3\":-2.46,\"key4\":{\"key5\":true,\"key6\":{\"key7\":0.01},\"key8\":[\"a\",false,null,9,10.23,-58.24]}}, arg 2: {}, arg 3: [], arg 4: false, arg 5: null" },
         { "header": "On Chain", "prompt": "0" },
         { "header": "Using Gas", "prompt": "at most 600 at price 1.0e-5" },
         { "header": "Transaction hash", "prompt": "5RygRqoczKtecEebMtaPLrulHa5aprNcjkRhMAAogNc" },
         { "header": "Sign for Address", "prompt": "ffd8cd79deb956fa3c7d9be0f836f20ac84b140168a087a842be4760e40e2b1c" },
         {
           "text": "Sign Transaction?",
           "x": 19,
           "y": 11,
         },
         {
           "text": "Confirm",
           "x": 43,
           "y": 11,
         }
       ]
     ));

  it("can sign multiple arbitrary caps",
     testTransaction(
       "0/0",
       '{"networkId":"mainnet01","payload":{"exec":{"data":{},"code":"(coin.transfer \\"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790\\" \\"9790d119589a26114e1a42d92598b3f632551c566819ec48e0e8c54dae6ebb42\\" 11.0)"}},"signers":[{"pubKey":"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790","clist":[{"args":[],"name":"coin.GAS"},{"args":[],"name":"mycoin.MY_TRANSFER0"},{"args":["83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790"],"name":"mycoin.MY_TRANSFER1"},{"args":["83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790","second arg"],"name":"mycoin.MY_TRANSFER2"},{"args":["83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790","second arg",22.2],"name":"mycoin.MY_TRANSFER3"},{"args":["83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790","second arg",5000,22.2],"name":"mycoin.MY_TRANSFER4"}]}],"meta":{"creationTime":1634009214,"ttl":28800,"gasLimit":600,"chainId":"0","gasPrice":1.0e-5,"sender":"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790"},"nonce":"\\"2021-10-12T03:27:53.700Z\\""}',
       [
         { "header": "Signing", "prompt": "Transaction" },
         { "header": "On Network", "prompt": "mainnet01" },
         { "header": "Requiring", "prompt": "Capabilities" },
         { "header": "Of Key", "prompt": "83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790" },
         { "header": "Paying Gas", "prompt": " " },
         { "header": "Unknown Capability 1", "prompt": "name: mycoin.MY_TRANSFER0, no args" },
         { "header": "Unknown Capability 2", "prompt": "name: mycoin.MY_TRANSFER1, arg 1: \"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790\"" },
         { "header": "Unknown Capability 3", "prompt": "name: mycoin.MY_TRANSFER2, arg 1: \"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790\", arg 2: \"second arg\"" },
         { "header": "Unknown Capability 4", "prompt": "name: mycoin.MY_TRANSFER3, arg 1: \"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790\", arg 2: \"second arg\", arg 3: 22.2" },
         { "header": "Unknown Capability 5", "prompt": "name: mycoin.MY_TRANSFER4, arg 1: \"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790\", arg 2: \"second arg\", arg 3: 5000, arg 4: 22.2" },
         { "header": "On Chain", "prompt": "0" },
         { "header": "Using Gas", "prompt": "at most 600 at price 1.0e-5" },
         { "header": "Transaction hash", "prompt": "QJDO0ks635Xpnq2GC85cqoQUxLgESujMgun7NUgrf5E" },
         { "header": "Sign for Address", "prompt": "ffd8cd79deb956fa3c7d9be0f836f20ac84b140168a087a842be4760e40e2b1c" },
         {
           "text": "Sign Transaction?",
           "x": 19,
           "y": 11,
         },
         {
           "text": "Confirm",
           "x": 43,
           "y": 11,
         }
       ]
     ));

  it("can sign multiple arbitrary caps along with multiple transfers",
     testTransaction(
       "0/0",
       '{"networkId":"mainnet01","payload":{"exec":{"data":{},"code":"(coin.transfer \\"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790\\" \\"9790d119589a26114e1a42d92598b3f632551c566819ec48e0e8c54dae6ebb42\\" 11.0)"}},"signers":[{"pubKey":"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790","clist":[{"args":[],"name":"coin.GAS"},{"args":[],"name":"mycoin.MY_TRANSFER0"},{"args":["83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790"],"name":"mycoin.MY_TRANSFER1"},{"args":["83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790","83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471791",4],"name":"coin.TRANSFER"},{"args":["83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790","83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471791",22.2,"4"],"name":"coin.TRANSFER_XCHAIN"},{"args":["83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790","83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471792",5000,"0"],"name":"mycoin.MY_TRANSFER4"}]}],"meta":{"creationTime":1634009214,"ttl":28800,"gasLimit":600,"chainId":"0","gasPrice":1.0e-5,"sender":"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790"},"nonce":"\\"2021-10-12T03:27:53.700Z\\""}',
       [
         { "header": "Signing", "prompt": "Transaction" },
         { "header": "On Network", "prompt": "mainnet01" },
         { "header": "Requiring", "prompt": "Capabilities" },
         { "header": "Of Key", "prompt": "83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790" },
         { "header": "Paying Gas", "prompt": " " },
         { "header": "Unknown Capability 1", "prompt": "name: mycoin.MY_TRANSFER0, no args" },
         { "header": "Unknown Capability 2", "prompt": "name: mycoin.MY_TRANSFER1, arg 1: \"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790\"" },
         { "header": "Transfer 1", "prompt": "4 from \"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790\" to \"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471791\""},
         { "header": "Transfer 2", "prompt": "Cross-chain 22.2 from \"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790\" to \"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471791\" to chain \"4\""},
         { "header": "Unknown Capability 3", "prompt": "name: mycoin.MY_TRANSFER4, arg 1: \"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790\", arg 2: \"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471792\", arg 3: 5000, arg 4: \"0\"" },
         { "header": "On Chain", "prompt": "0" },
         { "header": "Using Gas", "prompt": "at most 600 at price 1.0e-5" },
         { "header": "Transaction hash", "prompt": "yMXcVG1vcnLrbtdiKHI1MAYgrBgoDqr15YSRID70DyU" },
         { "header": "Sign for Address", "prompt": "ffd8cd79deb956fa3c7d9be0f836f20ac84b140168a087a842be4760e40e2b1c" },
         {
           "text": "Sign Transaction?",
           "x": 19,
           "y": 11,
         },
         {
           "text": "Confirm",
           "x": 43,
           "y": 11,
         }
       ]
     ));
  it("can sign an arbitrary cap with large number of args, showing warning",
     testTransaction(
       "0/0",
       '{"networkId":"mainnet01","payload":{"exec":{"data":{},"code":"(coin.transfer \\"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790\\" \\"9790d119589a26114e1a42d92598b3f632551c566819ec48e0e8c54dae6ebb42\\" 11.0)"}},"signers":[{"pubKey":"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790","clist":[{"args":[],"name":"coin.GAS"},{"args":["83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790","adfas",4,5,6,7,8],"name":"mycoin.MY_TRANSFER"}]}],"meta":{"creationTime":1634009214,"ttl":28800,"gasLimit":600,"chainId":"0","gasPrice":1.0e-5,"sender":"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790"},"nonce":"\\"2021-10-12T03:27:53.700Z\\""}',
       [
         { "header": "Signing", "prompt": "Transaction" },
         { "header": "On Network", "prompt": "mainnet01" },
         { "header": "Requiring", "prompt": "Capabilities" },
         { "header": "Of Key", "prompt": "83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790" },
         { "header": "Paying Gas", "prompt": " " },
         { "header": "Unknown Capability 1", "prompt": "name: mycoin.MY_TRANSFER, args cannot be displayed on Ledger" },
         { "header": "On Chain", "prompt": "0" },
         { "header": "Using Gas", "prompt": "at most 600 at price 1.0e-5" },
         { "header": "WARNING", "prompt": WARNING_FOR_CAP_NOT_SHOWN },
         { "header": "Transaction hash", "prompt": "Y2q38WX4sd5fWzw2knr7mfAltsaYxhWnDGtFaZ7NV40" },
         { "header": "Sign for Address", "prompt": "ffd8cd79deb956fa3c7d9be0f836f20ac84b140168a087a842be4760e40e2b1c" },
         {
           "text": "Sign Transaction?",
           "x": 19,
           "y": 11,
         },
         {
           "text": "Confirm",
           "x": 43,
           "y": 11,
         }
       ]
     ));

  it("can sign an arbitrary cap with BIG JSON in args, showing warning", async function () {
    this.timeout(60*1000);
    let path = "0/0";
    let file = "marmalade-tx.json";
    let prompts =
       [
         { "header": "Signing", "prompt": "Transaction" },
         { "header": "On Network", "prompt": "mainnet01" },
         { "header": "Requiring", "prompt": "Capabilities" },
         { "header": "Of Key", "prompt": "83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790" },
         { "header": "Paying Gas", "prompt": " " },
         { "header": "Unknown Capability 1", "prompt": "name: marmalade.ledger.transfer, args cannot be displayed on Ledger" },
         { "header": "On Chain", "prompt": "0" },
         { "header": "Using Gas", "prompt": "at most 600 at price 1.0e-5" },
         { "header": "WARNING", "prompt": WARNING_FOR_CAP_NOT_SHOWN },
         { "header": "Transaction hash", "prompt": "TX4rKze978k7T-MAzSJfTTHy1WCwAK8yi4RhZfAQzQE" },
         { "header": "Sign for Address", "prompt": "ffd8cd79deb956fa3c7d9be0f836f20ac84b140168a087a842be4760e40e2b1c" },
         {
           "text": "Sign Transaction?",
           "x": 19,
           "y": 11,
         },
         {
           "text": "Confirm",
           "x": 43,
           "y": 11,
         }
       ];

    await sendCommandAndAccept(
      async (kda : Kda) => {
        let pubkey = (await kda.getPublicKey(path)).publicKey;
        await Axios.delete("http://localhost:5000/events");

        let txn = await fs.readFileSync(file);
        let rv = await kda.signTransaction(path, txn);
        expect(rv.signature.length).to.equal(128);
        let hash = blake2b(32).update(txn).digest();
        let pass = nacl.crypto_sign_verify_detached(Buffer.from(rv.signature, 'hex'), hash, Buffer.from(pubkey, 'hex'));
        expect(pass).to.equal(true);
      }, prompts);
  });
})
