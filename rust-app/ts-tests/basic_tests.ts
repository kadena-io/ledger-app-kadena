import { expect } from 'chai';
import { describe, it } from 'mocha';
import SpeculosTransport from '@ledgerhq/hw-transport-node-speculos';
import Axios from 'axios';
import Transport from "./common";
import Kda from "hw-app-kda";

let ignoredScreens = [ "W e l c o m e", "Cancel", "Working...", "Exit" ]

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

describe('basic tests', async function() {

  before( async function() {
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
           console.log("Started pubkey get");
           let rv = await kda.signTransaction(path, Buffer.from(txn, "utf-8").toString("hex"));
           expect(rv.signature.length).to.equal(128);
         }, prompts);
     }
}

describe("Signing tests", function() {
  it("can sign a simple transfer",
     testTransaction(
       "0/0",
       '{"networkId":"mainnet01","payload":{"exec":{"data":{},"code":"(coin.transfer \\"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790\\" \\"9790d119589a26114e1a42d92598b3f632551c566819ec48e0e8c54dae6ebb42\\" 11.0)"}},"signers":[{"pubKey":"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790","clist":[{"args":[],"name":"coin.GAS"},{"args":["83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790","9790d119589a26114e1a42d92598b3f632551c566819ec48e0e8c54dae6ebb42",11],"name":"coin.TRANSFER"}]}],"meta":{"creationTime":1634009214,"ttl":28800,"gasLimit":600,"chainId":"0","gasPrice":1.0e-5,"sender":"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790"},"nonce":"\\"2021-10-12T03:27:53.700Z\\""}',
       [
         { "header": "Required", "prompt": "Signature" },
         { "header": "Paying Gas", "prompt": " " },
         { "header": "Transfer", "prompt": "11 from 83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790 to 9790d119589a26114e1a42d92598b3f632551c566819ec48e0e8" },
         { "header": "Transaction hash", "prompt": "B4ED85985F49CA6B48FF3F91362189CF6E3179823709F2990D837171EA2CB7CBC7D70E53D9BA7A93974C320723F839F125C064F578ADBD25" },
         { "header": "sign for address", "prompt": "ffd8cd79deb956fa3c7d9be0f836f20ac84b140168a087a842be4760e40e2b1c" },
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
            {
              "header": "Required",
              "prompt": "Signature",
            },
            {
              "header": "Transfer",
              "prompt": "2 from aab7d3e457f3f78480832d6ac4ace7387f460620a63a5b68c8c799d6bff1566a to 4c310df6224d674d80463a29cde00cb0ecfb71e0cfdce494243a6",
            },
            {
              "header": "Paying Gas",
              "prompt": " ",
            },
            {
              "header": "Transaction hash",
              "prompt": "C9FF121BBF443701A5E31C1F799F044F09B65B0D0CDC38F062F3E81E899485881AAE2646CD8FEAC863DD42B1EE7139BAB739E23E63B5350A",
            },
            {
              "header": "sign for address",
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
         {
           "header": "Required",
           "prompt": "Signature",
         },
         {
           "header": "Paying Gas",
           "prompt": " ",
         },
         {
           "header": "Transfer",
           "prompt": "4.98340488 from e4a1b2980c086c4551ab7d2148cf56e9774c64eb86f795d5fd83e39ccfd2ec66 to 875e4493e19c8721583bfb46f0768f10266ebcca33c4a0e04bc099a7044a",
         },
         {
           "header": "Transaction hash",
           "prompt": "770D90DD7B5AE4B33DFE0332F05F6B5C6EF82FA0E1FF57188D51061367E02477164054BF6028A67464F74967F4C2E2026DF3CE132F137D38",
         },
         {
           "header": "sign for address",
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
       '{"networkId":"mainnet01","payload":{"exec":{"data":{"recp-ks":{"pred":"keys-all","keys":["875e4493e19c8721583bfb46f0768f10266ebcca33c4a0e04bc099a7044a90f7"]}},"code":"(coin.transfer-create \\"73580ffb3e5ca9859442395d4c1cb0bf3aa4e7246564ce943b7ae508b3ee7c03\\" \\"875e4493e19c8721583bfb46f0768f10266ebcca33c4a0e04bc099a7044a90f7\\" (read-keyset \\"recp-ks\\") 4.89093455)"}},"signers":[{"pubKey":"73580ffb3e5ca9859442395d4c1cb0bf3aa4e7246564ce943b7ae508b3ee7c03","clist":[{"args":[],"name":"coin.GAS"},{"args":["73580ffb3e5ca9859442395d4c1cb0bf3aa4e7246564ce943b7ae508b3ee7c03","875e4493e19c8721583bfb46f0768f10266ebcca33c4a0e04bc099a7044a90f7",4.89093455],"name":"coin.TRANSFER"}]}],"meta":{"creationTime":1634009098,"ttl":28800,"gasLimit":60000,"chainId":"0","gasPrice":1.0e-6,"sender":"73580ffb3e5ca9859442395d4c1cb0bf3aa4e7246564ce943b7ae508b3ee7c03"},"nonce":"\\"1634009113073\\""}',
       [
         {
           "header": "Required",
           "prompt": "Signature",
         },
         {
           "header": "Paying Gas",
           "prompt": " ",
         },
         {
           "header": "Transfer",
           "prompt": "4.89093455 from 73580ffb3e5ca9859442395d4c1cb0bf3aa4e7246564ce943b7ae508b3ee7c03 to 875e4493e19c8721583bfb46f0768f10266ebcca33c4a0e04bc099a7044a",
         },
         {
           "header": "Transaction hash",
           "prompt": "C68B15CDB44020F985AFB0AED6996EC4E9DE2999E1B526BD8CA1AACEC17081CA5EB3794FDC7B82D9A453E97A6F2653C1464A05F734ADB462",
         },
         {
           "header": "sign for address",
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
         {
           "header": "Required",
           "prompt": "Signature",
         },
         {
           "header": "Paying Gas",
           "prompt": " ",
         },
         {
           "header": "Rotate for account",
           "prompt": "d3300d284f4bcfbc91555184ef026a356e57ff0fa97b5e6c",
         },
         {
           "header": "Transaction hash",
           "prompt": "E477DDF7DFD4C214DFA13A6CA405331E0159C9D129E5A22B05CF2257766A3126AD05BF6D4C4E5ACB4F306CD7AE807B8231B46CFEB62866D0",
         },
         {
           "header": "sign for address",
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

});
