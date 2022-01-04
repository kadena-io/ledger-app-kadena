import { expect } from 'chai';
import { describe, it } from 'mocha';
import SpeculosTransport from '@ledgerhq/hw-transport-node-speculos';
import Axios from 'axios';
import Transport from "./common";
import Kda from "hw-app-kda";

import * as blake2b from "blake2b";
// import libsodium from "libsodium-wrappers";

// await libsodium.ready;
import { instantiate, Nacl } from "js-nacl";


let nacl : Nacl =null;

let ignoredScreens = [ "W e l c o m e", "Cancel", "Working...", "Exit", "Kadena 0.0.4"]

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
         { "header": "Requiring", "prompt": "Capabilities" },
         { "header": "Of Key", "prompt": "83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790" },
         { "header": "Paying Gas", "prompt": " " },
         { "header": "Transfer", "prompt": "11 from 83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790 to 9790d119589a26114e1a42d92598b3f632551c566819ec48e0e8c54dae6ebb42" },
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
            { "header": "Requiring", "prompt": "Capabilities" },
            { "header": "Of Key", "prompt": "aab7d3e457f3f78480832d6ac4ace7387f460620a63a5b68c8c799d6bff1566a" },
            {
              "header": "Transfer",
              "prompt": "2 from aab7d3e457f3f78480832d6ac4ace7387f460620a63a5b68c8c799d6bff1566a to 4c310df6224d674d80463a29cde00cb0ecfb71e0cfdce494243a61b8ea572dfd",
            },
            {
              "header": "Paying Gas",
              "prompt": " ",
            },
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
          it("can sign a transfer-create",
             testTransaction(
       "0/0",
       '{"networkId":"mainnet01","payload":{"exec":{"data":{"recp-ks":{"pred":"keys-all","keys":["875e4493e19c8721583bfb46f0768f10266ebcca33c4a0e04bc099a7044a90f7"]}},"code":"(coin.transfer-create \\"e4a1b2980c086c4551ab7d2148cf56e9774c64eb86f795d5fd83e39ccfd2ec66\\" \\"875e4493e19c8721583bfb46f0768f10266ebcca33c4a0e04bc099a7044a90f7\\" (read-keyset \\"recp-ks\\") 4.98340488)"}},"signers":[{"pubKey":"e4a1b2980c086c4551ab7d2148cf56e9774c64eb86f795d5fd83e39ccfd2ec66","clist":[{"args":[],"name":"coin.GAS"},{"args":["e4a1b2980c086c4551ab7d2148cf56e9774c64eb86f795d5fd83e39ccfd2ec66","875e4493e19c8721583bfb46f0768f10266ebcca33c4a0e04bc099a7044a90f7",4.98340488],"name":"coin.TRANSFER"}]}],"meta":{"creationTime":1634009142,"ttl":28800,"gasLimit":60000,"chainId":"0","gasPrice":1.0e-6,"sender":"e4a1b2980c086c4551ab7d2148cf56e9774c64eb86f795d5fd83e39ccfd2ec66"},"nonce":"\\"1634009156943\\""}',
       [
         { "header": "Signing", "prompt": "Transaction" },
         { "header": "Requiring", "prompt": "Capabilities" },
         { "header": "Of Key", "prompt": "e4a1b2980c086c4551ab7d2148cf56e9774c64eb86f795d5fd83e39ccfd2ec66" },
         {
           "header": "Paying Gas",
           "prompt": " ",
         },
         {
           "header": "Transfer",
           "prompt": "4.98340488 from e4a1b2980c086c4551ab7d2148cf56e9774c64eb86f795d5fd83e39ccfd2ec66 to 875e4493e19c8721583bfb46f0768f10266ebcca33c4a0e04bc099a7044a90f7",
         },
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
           "header": "Transfer",
           "prompt": "4.89093455 from 73580ffb3e5ca9859442395d4c1cb0bf3aa4e7246564ce943b7ae508b3ee7c03 to 875e4493e19c8721583bfb46f0768f10266ebcca33c4a0e04bc099a7044a90f7",
         },
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
         { "header": "Requiring", "prompt": "Capabilities" },
         { "header": "Of Key", "prompt": "81b4511b257fb975dace13e823c257c17ac6a695da65f91b6036d6e1429268fc" },
         {
           "header": "Paying Gas",
           "prompt": " ",
         },
         {
           "header": "Rotate for account",
           "prompt": "d3300d284f4bcfbc91555184ef026a356e57ff0fa97b5e6c9830750892cd3093",
         },
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
            "44'/626'/0'", "{\"networkId\":\"testnet04\",\"payload\":{\"exec\":{\"data\":{\"ks\":{\"keys\":[\"ffd8cd79deb956fa3c7d9be0f836f20ac84b140168a087a842be4760e40e2b1c\"],\"pred\":\"keys-all\"}},\"code\":\"(coin.transfer-crosschain \\\"ffd8cd79deb956fa3c7d9be0f836f20ac84b140168a087a842be4760e40e2b1c\\\" \\\"ffd8cd79deb956fa3c7d9be0f836f20ac84b140168a087a842be4760e40e2b1c\\\" (read-keyset \\\"ks\\\") \\\"0\\\" 1.0)\"}},\"signers\":[{\"pubKey\":\"ffd8cd79deb956fa3c7d9be0f836f20ac84b140168a087a842be4760e40e2b1c\"}],\"meta\":{\"creationTime\":1640290267,\"ttl\":28800,\"gasLimit\":600,\"chainId\":\"1\",\"gasPrice\":0.00001,\"sender\":\"ffd8cd79deb956fa3c7d9be0f836f20ac84b140168a087a842be4760e40e2b1c\"},\"nonce\":\"\\\"\\\\\\\"2021-12-23T20:12:06.664Z\\\\\\\"\\\"\"}",
            [
              {
                "header": "Signing",
                "prompt": "Transaction",
              },
              {
                "header": "Requiring",
                "prompt": "Capabilities",
              },
              {
                "header": "Of Key",
                "prompt": "ffd8cd79deb956fa3c7d9be0f836f20ac84b140168a087a842be4760e40e2b1c",
              },
              {
                "header": "WARNING",
                "prompt": "UNSAFE TRANSACTION. This transaction's code was not recognized and does not limit capabilities for all signers. Signing this transaction may make arbitrary actions on the chain including loss of all funds.",
              },
              {
                "header": "Transaction hash",
                "prompt": "MM7O6sd6BVZgeXFFqjVXHnfZ_Q2QxCEexoGeNgTj4WM",
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
});
