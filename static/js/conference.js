const joinBtn = document.getElementById("join-btn");
const leaveBtn = document.getElementById("leave-btn");
const participantsEl = document.getElementById("participants");
const teamId = parseInt(joinBtn?.dataset.teamId ?? "0", 10);

const socket = io();
const peerConnections = new Map();
let localStream = null;
let joined = false;

const rtcConfig = {
  iceServers: [{ urls: "stun:stun.l.google.com:19302" }],
};

function createParticipantElement(id, label) {
  let node = document.getElementById(`participant-${id}`);
  if (!node) {
    node = document.createElement("div");
    node.className = "participant";
    node.id = `participant-${id}`;
    node.innerHTML = `<h4>${label}</h4>`;
    const audio = document.createElement("audio");
    audio.autoplay = true;
    audio.controls = true;
    audio.playsInline = true;
    node.appendChild(audio);
    participantsEl.appendChild(node);
  }
  return node;
}

function setParticipantStream(id, stream, label) {
  const element = createParticipantElement(id, label);
  const audio = element.querySelector("audio");
  if (audio.srcObject !== stream) {
    audio.srcObject = stream;
    audio.muted = label === "Вы";
  }
}

function removeParticipant(id) {
  const existing = document.getElementById(`participant-${id}`);
  if (existing) {
    const audio = existing.querySelector("audio");
    if (audio?.srcObject instanceof MediaStream) {
      audio.srcObject.getTracks().forEach((track) => track.stop());
    }
    existing.remove();
  }
}

function getDisplayName(id) {
  return `Участник ${id.slice(-6)}`;
}

function ensurePeerConnection(targetId) {
  if (peerConnections.has(targetId)) {
    return peerConnections.get(targetId);
  }
  const pc = new RTCPeerConnection(rtcConfig);
  localStream.getTracks().forEach((track) => pc.addTrack(track, localStream));

  pc.ontrack = (event) => {
    const [stream] = event.streams;
    setParticipantStream(targetId, stream, getDisplayName(targetId));
  };

  pc.onicecandidate = (event) => {
    if (event.candidate) {
      socket.emit("candidate", {
        teamId,
        target: targetId,
        candidate: event.candidate,
      });
    }
  };

  pc.onconnectionstatechange = () => {
    if (pc.connectionState === "disconnected" || pc.connectionState === "failed") {
      removeParticipant(targetId);
      pc.close();
      peerConnections.delete(targetId);
    }
  };

  peerConnections.set(targetId, pc);
  return pc;
}

async function createAndSendOffer(targetId) {
  const pc = ensurePeerConnection(targetId);
  const offer = await pc.createOffer();
  await pc.setLocalDescription(offer);
  socket.emit("offer", { teamId, target: targetId, sdp: offer });
}

joinBtn?.addEventListener("click", async () => {
  if (joined) return;
  try {
    localStream = await navigator.mediaDevices.getUserMedia({ audio: true });
    setParticipantStream("self", localStream, "Вы");
    socket.emit("join", { teamId });
    joinBtn.disabled = true;
    leaveBtn.disabled = false;
    joined = true;
  } catch (error) {
    console.error("Microphone access error", error);
    alert("Не удалось получить доступ к микрофону. Проверьте настройки браузера.");
  }
});

leaveBtn?.addEventListener("click", () => {
  if (!joined) return;
  socket.emit("leave", { teamId });
  joined = false;
  joinBtn.disabled = false;
  leaveBtn.disabled = true;

  peerConnections.forEach((pc, id) => {
    pc.close();
    removeParticipant(id);
  });
  peerConnections.clear();

  if (localStream) {
    localStream.getTracks().forEach((track) => track.stop());
    localStream = null;
  }
  removeParticipant("self");
});

socket.on("participants", async ({ members }) => {
  if (!joined) return;
  for (const memberId of members ?? []) {
    await createAndSendOffer(memberId);
  }
});

socket.on("participant-joined", async ({ sid }) => {
  if (!joined) return;
  await createAndSendOffer(sid);
});

socket.on("participant-left", ({ sid }) => {
  const pc = peerConnections.get(sid);
  if (pc) {
    pc.close();
    peerConnections.delete(sid);
  }
  removeParticipant(sid);
});

socket.on("offer", async ({ from, sdp }) => {
  if (!joined) return;
  const pc = ensurePeerConnection(from);
  await pc.setRemoteDescription(new RTCSessionDescription(sdp));
  const answer = await pc.createAnswer();
  await pc.setLocalDescription(answer);
  socket.emit("answer", { teamId, target: from, sdp: answer });
});

socket.on("answer", async ({ from, sdp }) => {
  const pc = peerConnections.get(from);
  if (!pc) return;
  await pc.setRemoteDescription(new RTCSessionDescription(sdp));
});

socket.on("candidate", async ({ from, candidate }) => {
  const pc = peerConnections.get(from);
  if (!pc || !candidate) return;
  try {
    await pc.addIceCandidate(new RTCIceCandidate(candidate));
  } catch (error) {
    console.error("Failed to add ICE candidate", error);
  }
});

window.addEventListener("beforeunload", () => {
  if (joined) {
    socket.emit("leave", { teamId });
  }
});
