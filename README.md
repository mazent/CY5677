# CY5677
An alternative to cysmart

[Here](https://community.cypress.com/thread/36215) you can download
`BLE_4_2_Dongle_CySmart_256K.7z.zip`, that should be the source code
for cy5670 (different baud rate)

From [this](https://community.cypress.com/message/143227) post you can
reach  a python [script](https://github.com/odwdinc/Cy_BleBridge) for
the cy5677 dongle: it is quite different from this

If you run the script, it scans for ble devices printing the list

## Details

### Init

`CyBle_Start` is called at the beginning passing `CapSenseClientEventHandler` and
when executing `Cmd_Init_Ble_Stack_Api`, this time with `CyS_GenericEventHandler`, that
forwards events to the pc. `Cmd_Init_Ble_Stack_Api` calls `CyBle_Stop`, so 
you can invoke it whenever you want. 

### Serialization

The thread: 
1. manages access to the serial port 
2. serializes access to internal variables avoiding locks

### Command execution

A command is composed by an opcode, optional parameters and a queue

The flow of execution is:
1. API puts a command on the queue and wait for the response on its queue
2. the thread get the command, compose the packet and send it to the serial port
3. the thread collects the events and when it receives EVT_COMMAND_COMPLETE sends the result to the command's queue
4. API completes the operation and returns the result to the caller

### Callbacks

You can override:
1. `scan_progress_cb`: it will receive advertisements when you scan for ble devices
2. `gap_auth_req_cb`: the peripheral is asking for authentication
3. `gap_passkey_entry_request_cb`: you has to send passkey to be used during the pairing procedure
4. `gap_auth_resul_cb`: authentication procedure ended with success(0) or failure
5. `gap_device_disconnected_cb`: peripheral disconnection
