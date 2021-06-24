#!/usr/bin/env python3

import json

outFile = '/tmp/x.html'
inFile = '/tmp/x.json'
mode = 'html'
regex = '.*' # TODO(connordp): Actually implement this.
htmlBase = './table.html'


if __name__ == '__main__':

    with open(inFile, 'r') as fd:
        obj = json.load(fd)
    with open(htmlBase, 'r') as fd:
        html = fd.read()

    # TODO(connordp): Template engines exist

    data = ''
    events = obj['events']
    i = 1
    for event in events:
        # Only parse events containg the keyword open|access
        onEnter = event['onEnter']
        onExit = event['onExit']
        if onEnter.get('syscall') is not None: # When syscall isn't defined, onEnter == {}. Bug?
            syscall = onEnter['syscall']['name']

            eventData = "<tr>"
            eventData += f'<td>{i}</td>'
            eventData += f'<td>{onEnter["tid"]}</td>'
            eventData += f'<td>{onEnter["syscall"]["name"]}</td>'
            if onEnter["syscall"].get('arguments') is not None:
                arguments = onEnter["syscall"]["arguments"]
                x = ""
                i = 0
                for arg in arguments:
                    x += f'{arguments[i]["arg"]}={arguments[i]["value"]},'
                    i += 1
                x = x[:-1]
                eventData += f'<td>{x}</td>'
            else:
                eventData += '<td></td>'
            eventData += f'<td>{onExit["syscall"]["returnValue"]}</td>'
        i = i + 1


        eventData += "</tr>"
        data += eventData

    html = html.replace('<!--   %FINDME%-->', data)
    with open(outFile, 'w') as fd:
        fd.write(html)

    print('Wrote event data to ' + outFile)