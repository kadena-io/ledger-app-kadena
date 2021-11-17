import { expect } from 'chai';
import { describe, it } from 'mocha';
import SpeculosTransport from '@ledgerhq/hw-transport-node-speculos';
import Axios from 'axios';
import Transport from "./common";
import Kda from "hw-app-kda";

let setAcceptAutomationRules = async function() {
    await Axios.post("http://localhost:5000/automation", {
      version: 1,
      rules: [
        { "text": "W e l c o m e", "actions": [] },
        { "text": "Confirm", "actions": [ [ "button", 1, true ], [ "button", 2, true ], [ "button", 2, false ], [ "button", 1, false ] ]},
        { "actions": [ [ "button", 2, true ], [ "button", 2, false ] ]}
      ]
    });
}

let sendCommandAndAccept = async function(command : any, prompts : any) {
    await setAcceptAutomationRules();
    await Axios.delete("http://localhost:5000/events");

    let transport = await Transport.open("http://localhost:5000/apdu");
    let kda = new Kda(transport);
    
    //await new Promise(resolve => setTimeout(resolve, 100));
    
    await command(kda);
    
    //await new Promise(resolve => setTimeout(resolve, 100));


    expect(((await Axios.get("http://localhost:5000/events")).data["events"] as [any]).filter((a : any) => a["text"] != "W e l c o m e")).to.deep.equal(prompts);
}

describe('basic tests', () => {
  afterEach( async function() {
    console.log("Clearing settings");
    await Axios.post("http://localhost:5000/automation", {version: 1, rules: []});
    await Axios.delete("http://localhost:5000/events");
  });

  it('provides a public key', async () => {

    await sendCommandAndAccept(async (kda : Kda) => {
      console.log("Started pubkey get");
      let rv = await kda.getPublicKey("0");
      console.log("Reached Pubkey Got");
      expect(rv.publicKey).to.equal("046f760e57383e3b5900f7c23b78a424e74bebbe9b7b46316da7c0b4b9c2c9301c0c076310eda30506141dd47c2d0a8a1d7ca2542482926ae23b781546193b9616");
      return;
    }, [
        {
          "text": "Provide Public Key",
          "x": 16,
          "y": 11
        },
        {
          "text": "pkh-CBB24246905B6BA63DB45BE62EDAEA0BEC58166BF39F9492CD199D5479686B2",
          "x": -48,
          "y": 11
        },
        {
          "text": "Confirm",
          "x": 43,
          "y": 11
        }
    ]);
  });
  
  it('provides a public key', async () => {
  await sendCommandAndAccept(async (kda : Kda) => {
      console.log("Started pubkey get");
      let rv = await kda.getPublicKey("0");
      console.log("Reached Pubkey Got");
      expect(rv.publicKey).to.equal("046f760e57383e3b5900f7c23b78a424e74bebbe9b7b46316da7c0b4b9c2c9301c0c076310eda30506141dd47c2d0a8a1d7ca2542482926ae23b781546193b9616");
      return;
    }, [
        {
          "text": "Provide Public Key",
          "x": 16,
          "y": 11
        },
        {
          "text": "pkh-CBB24246905B6BA63DB45BE62EDAEA0BEC58166BF39F9492CD199D5479686B2",
          "x": -48,
          "y": 11
        },
        {
          "text": "Confirm",
          "x": 43,
          "y": 11
        }
    ]);
  });

  it('runs a test', async () => { 
    
    await setAcceptAutomationRules();
    await Axios.delete("http://localhost:5000/events");

    let transport = await Transport.open("http://localhost:5000/apdu");
    let kda = new Kda(transport);
    
    let rv = await kda.getPublicKey("0/0");
   
    await Axios.post("http://localhost:5000/automation", {version: 1, rules: []});

    expect(rv.publicKey).to.equal("04e96341109fdba54691303553ee95b371d9745410f1090055fb7c0aa9e564445483f78cb81526e27ab7869fcd996eb8bd39add229b41f9e30bccccdc00a9d6c4c");
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
    await Axios.delete("http://localhost:5000/events");
  });
});

function testTransaction(path: string, txn: string, prompts: any[]) {
     return async () => {
       await sendCommandAndAccept(
         async (kda : Kda) => {
           console.log("Started pubkey get");
           let rv = await kda.signTransaction(path, Buffer.from(txn, "utf-8").toString("hex"));
         }, prompts);
     }
}

describe("Signing tests", function() {
  it("can sign a simple transfer",
     testTransaction(
       "0/0",
       '{"networkId":"mainnet01","payload":{"exec":{"data":{},"code":"(coin.transfer \"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790\" \"9790d119589a26114e1a42d92598b3f632551c566819ec48e0e8c54dae6ebb42\" 11.0)"}},"signers":[{"pubKey":"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790","clist":[{"args":[],"name":"coin.GAS"},{"args":["83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790","9790d119589a26114e1a42d92598b3f632551c566819ec48e0e8c54dae6ebb42",11],"name":"coin.TRANSFER"}]}],"meta":{"creationTime":1634009214,"ttl":28800,"gasLimit":600,"chainId":"0","gasPrice":1.0e-5,"sender":"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790"},"nonce":"\"2021-10-12T03:27:53.700Z\""}',
       []));
  it("can sign a different simple transfer",
     testTransaction(
       "0/0",
       '{"networkId":"mainnet01","payload":{"exec":{"data":{},"code":"(coin.transfer \"aab7d3e457f3f78480832d6ac4ace7387f460620a63a5b68c8c799d6bff1566a\" \"4c310df6224d674d80463a29cde00cb0ecfb71e0cfdce494243a61b8ea572dfd\" 2.0)"}},"signers":[{"pubKey":"aab7d3e457f3f78480832d6ac4ace7387f460620a63a5b68c8c799d6bff1566a","clist":[{"args":["aab7d3e457f3f78480832d6ac4ace7387f460620a63a5b68c8c799d6bff1566a","4c310df6224d674d80463a29cde00cb0ecfb71e0cfdce494243a61b8ea572dfd",2],"name":"coin.TRANSFER"},{"args":[],"name":"coin.GAS"}]}],"meta":{"creationTime":1634009195,"ttl":900,"gasLimit":600,"chainId":"0","gasPrice":1.0e-6,"sender":"aab7d3e457f3f78480832d6ac4ace7387f460620a63a5b68c8c799d6bff1566a"},"nonce":"\"2021-10-12T03:27:35.231Z\""}',
       []));
  it("can sign a transfer-create",
     testTransaction(
       "0/0",
       '{"networkId":"mainnet01","payload":{"exec":{"data":{"recp-ks":{"pred":"keys-all","keys":["875e4493e19c8721583bfb46f0768f10266ebcca33c4a0e04bc099a7044a90f7"]}},"code":"(coin.transfer-create \"e4a1b2980c086c4551ab7d2148cf56e9774c64eb86f795d5fd83e39ccfd2ec66\" \"875e4493e19c8721583bfb46f0768f10266ebcca33c4a0e04bc099a7044a90f7\" (read-keyset \"recp-ks\") 4.98340488)"}},"signers":[{"pubKey":"e4a1b2980c086c4551ab7d2148cf56e9774c64eb86f795d5fd83e39ccfd2ec66","clist":[{"args":[],"name":"coin.GAS"},{"args":["e4a1b2980c086c4551ab7d2148cf56e9774c64eb86f795d5fd83e39ccfd2ec66","875e4493e19c8721583bfb46f0768f10266ebcca33c4a0e04bc099a7044a90f7",4.98340488],"name":"coin.TRANSFER"}]}],"meta":{"creationTime":1634009142,"ttl":28800,"gasLimit":60000,"chainId":"0","gasPrice":1.0e-6,"sender":"e4a1b2980c086c4551ab7d2148cf56e9774c64eb86f795d5fd83e39ccfd2ec66"},"nonce":"\"1634009156943\""}',
       []));
  it("can sign a transfer-create",
     testTransaction(
       "0/0",
       '{"networkId":"mainnet01","payload":{"exec":{"data":{"recp-ks":{"pred":"keys-all","keys":["875e4493e19c8721583bfb46f0768f10266ebcca33c4a0e04bc099a7044a90f7"]}},"code":"(coin.transfer-create \"73580ffb3e5ca9859442395d4c1cb0bf3aa4e7246564ce943b7ae508b3ee7c03\" \"875e4493e19c8721583bfb46f0768f10266ebcca33c4a0e04bc099a7044a90f7\" (read-keyset \"recp-ks\") 4.89093455)"}},"signers":[{"pubKey":"73580ffb3e5ca9859442395d4c1cb0bf3aa4e7246564ce943b7ae508b3ee7c03","clist":[{"args":[],"name":"coin.GAS"},{"args":["73580ffb3e5ca9859442395d4c1cb0bf3aa4e7246564ce943b7ae508b3ee7c03","875e4493e19c8721583bfb46f0768f10266ebcca33c4a0e04bc099a7044a90f7",4.89093455],"name":"coin.TRANSFER"}]}],"meta":{"creationTime":1634009098,"ttl":28800,"gasLimit":60000,"chainId":"0","gasPrice":1.0e-6,"sender":"73580ffb3e5ca9859442395d4c1cb0bf3aa4e7246564ce943b7ae508b3ee7c03"},"nonce":"\"1634009113073\""}',
       []));

  it("can sign a rotate transaction",
     testTransaction(
       "0/0",
'{"networkId":"mainnet01","payload":{"exec":{"data":{"ks":{"pred":"keys-all","keys":["d3300d284f4bcfbc91555184ef026a356e57ff0fa97b5e6c9830750892cd3093"]}},"code":"(coin.rotate \"d3300d284f4bcfbc91555184ef026a356e57ff0fa97b5e6c9830750892cd3093\" (read-keyset \"ks\"))"}},"signers":[{"pubKey":"81b4511b257fb975dace13e823c257c17ac6a695da65f91b6036d6e1429268fc","clist":[{"args":[],"name":"coin.GAS"},{"args":["d3300d284f4bcfbc91555184ef026a356e57ff0fa97b5e6c9830750892cd3093"],"name":"coin.ROTATE"}]}],"meta":{"creationTime":1633466764,"ttl":28800,"gasLimit":1500,"chainId":"0","gasPrice":1.0e-5,"sender":"81b4511b257fb975dace13e823c257c17ac6a695da65f91b6036d6e1429268fc"},"nonce":"\"1633466764\""}',
       []));

});
