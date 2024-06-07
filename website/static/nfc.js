window.addEventListener(
    "message",
    (event) => {
      alert(event.origin);
    },
    false,
  );

function scanWristband() {
  window.postMessage("scanWristband", "*");
}