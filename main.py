import json
import frida
import signal
import sys

events = []


def signal_handler(sig, frame):
	buffer = json.dumps({
		"metadata": {
			"application": "TODO",
			"timeStarted": 1,
			"timeEnded": 5,
		},
		"events": events
	})
	with open('/tmp/x.json', 'w') as fd:
		fd.write(buffer)
	sys.exit(0)

# TODO: Add argument parser
# TODO: Syscall data should be passed to our frida script. RPC || Modify as required
if __name__ == '__main__':
	appname = 'your.app.name.here' # Can't push with this naturally
	agentPath = './agents/arm64.default.js'
	syscallData = './data/arm64.json'
	styledOutput = True

	with open(agentPath, 'r') as fd:
		agentCode = fd.read()
	with open(syscallData, 'r') as fd:
		syscalls = json.load(fd)


	def onMessage(message, payload):
		syscallContext = message['payload']
		events.append(syscallContext)


	device = frida.get_usb_device()
	pid = device.spawn([appname]) # TODO: Modify my initial script to support attaching and spawning
	session = device.attach(pid)
	script = session.create_script(agentCode)
	script.on("message", onMessage)
	script.load()
	device.resume(pid)

signal.signal(signal.SIGINT, signal_handler)
print('Control+C when your done, or the app crashes (TODO)')

while 1==1:
	input()