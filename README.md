# CY5677
An alternative to cysmart

[Here](https://community.cypress.com/thread/36215) you can download
`BLE_4_2_Dongle_CySmart_256K.7z.zip`, that should be the source code
for cy5670 (different baud rate)

From [this](https://community.cypress.com/message/143227) post you can
reach  a python [script](https://github.com/odwdinc/Cy_BleBridge) for
the cy5677 dongle: it is quite different

Here the serial port is managed by a thread: read and writes are serialized
using queues:
1. The command is posted to the command queue
2. `run` sends the command to the dongle
3. `run` reads the serial port, collects the data and pass them to `PROTO`
4. `run` invokes `PROTO` and closes the command sending the replay to its queue

You can override `notification` to receive notifications

If you run the script, it scans for ble devices printing the list
