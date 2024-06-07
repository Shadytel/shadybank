var appPort;

window.addEventListener(
    "message",
    (event) => {
      document.getElementById("status").innerText = event.data;
      appPort = event.ports[0];
    },
    false,
  );

function scanWristband() {
  appPort.postMessage("scanWristband");
}
