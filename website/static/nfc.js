var appPort;
var uid;
var chal;
var tagAuthState;
var nfc_token;
activate_wristband = false;

window.ontag = function () {}
window.onactivatesuccess = function () {}
window.onactivatefail = function () {}
window.nfcerror = function (msg) {}

async function handleAppMsg(event) {
  console.log(event.data);
  msg = JSON.parse(event.data);
  if (msg.msg == "newTag") {
    uid = msg.uid;
    // Initiate mutual auth
    tagAuthState = 1;
    //appPort.postMessage("{'msg': 'tagTransceive', 'txData': '1a00'}");
  } else if (msg.msg == "tagTransceiveResp") {
    if (tagAuthState == 1) {
      chal = msg.rxData.substring(2);
      data = new FormData();
      data.append("uid", uid);
      data.append("chal", chal);
      req = await fetch("/api/nfc_challenge", {
        method: "POST",
        body: data
      });
      resp = await req.json();
      tagAuthState = 2;
      appPort.postMessage("{'msg': 'tagTransceive', 'txData': 'af" + resp.resp + "'}");
    } else if (tagAuthState == 2) {
      data = new FormData();
      data.append("uid", uid);
      data.append("chal", chal);
      data.append("resp", msg.rxData.substring(2));
      req = await fetch("/api/nfc_response", {
        method: "POST",
        body: data
      });
      resp = await req.json();
      nfc_token = resp.nfc_token;
      window.ontag();

      if (activate_wristband) {
        data = new FormData();
        data.append("nfc_token", nfc_token);
        req = await fetch("/api/nfc_activate", {
          method: "POST",
          body: data,
          headers: {
            "Authorization": "Bearer " + document.getElementById("auth_token").value
          }
        });
        resp = await req.json();
        resp.msg = "tagBulkSend";
        tagAuthState = 3;
        appPort.postMessage(JSON.stringify(resp));
      }
    } 
  } else if (msg.msg == "tagBulkSendResp") {
    for (let i = 0; i < msg.resps.length; i++) {
      if (msg.resps[i] != '0a') {
        window.onactivatefail("Got response " + msg.resps[i] + " to message " + i);
        break;
      }
    }
    window.onactivatesuccess();
  } else if (msg.msg == "exception") {
    window.nfcerror(msg.str);
  } else {
    console.log(JSON.stringify(msg));
  }
}


window.addEventListener(
    "message",
    (event) => {
      appPort = event.ports[0];
      appPort.onmessage = handleAppMsg;
      appPort.postMessage("{'msg':'enableNFC'}");
    },
    false,
  );

