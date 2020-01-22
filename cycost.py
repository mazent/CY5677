# CySmt_protocol.h
# ====================================================================

# General Events
EVT_COMMAND_STATUS = 0x047E
EVT_COMMAND_COMPLETE = 0x047F
EVT_GET_DEVICE_ID_RESPONSE = 0x0400
EVT_GET_SUPPORTED_TOOL_VERSION_RESPONSE = 0x0401
EVT_GET_FIRMWARE_VERSION_RESPONSE = 0x0402
EVT_GET_BLE_STACK_VERSION_RESPONSE = 0x0403
EVT_REPORT_STACK_MISC_STATUS = 0x0404
EVT_GET_SUPPORTED_GAP_ROLES_RESPONSE = 0x0405
EVT_GET_CURRENT_GAP_ROLE_RESPONSE = 0x0406
EVT_GET_SUPPORTED_GATT_ROLES_RESPONSE = 0x0407
EVT_GET_CURRENT_GATT_ROLE_RESPONSE = 0x0408
EVT_GET_RSSI_RESPONSE = 0x0409
EVT_GET_DEVICE_DESCRIPTION_RESPONSE = 0x040A
EVT_GET_HARDWARE_VERSION_RESPONSE = 0x040B
EVT_GET_TX_POWER_RESPONSE = 0x040C

# FW specific events, not used by CySmart tool
HID_EP1_PACKET = 0x0461
HID_EP2_PACKET = 0x0462
AUDIO_REPORT = 0x0463
AUDIO_CONTROL_STATUS = 0x0464
AUDIO_SYNC_PACKET = 0x0465
AUDIO_RAW_DATA = 0x0466

# GATT Events
EVT_DISCOVER_ALL_PRIMARY_SERVICES_RESULT_PROGRESS = 0x0600
EVT_DISCOVER_PRIMARY_SERVICES_BY_UUID_RESULT_PROGRESS = 0x0601
EVT_FIND_INDLUDED_SERVICES_RESULT_PROGRESS = 0x0602
EVT_DISCOVER_ALL_CHARACTERISTICS_RESULT_PROGRESS = 0x0603
EVT_DISCOVER_CHARACTERISTICS_BY_UUID_RESULT_PROGRESS = 0x0604
EVT_DISCOVER_ALL_CHARACTERISTIC_DESCRIPTORS_RESULT_PROGRESS = 0x0605
EVT_READ_CHARACTERISTIC_VALUE_RESPONSE = 0x0606
EVT_READ_USING_CHARACTERISTIC_UUID_RESPONSE = 0x0607
EVT_READ_LONG_CHARACTERISTIC_VALUE_RESPONSE = 0x0608
EVT_READ_MULTIPLE_CHARACTERISTIC_VALUES_RESPONSE = 0x0609
EVT_READ_CHARACTERISTIC_DESCRIPTOR_RESPONSE = 0x060A
EVT_READ_LONG_CHARACTERISTIC_DESCRIPTOR_RESPONSE = 0x060B
EVT_CHARACTERISTIC_VALUE_NOTIFICATION = 0x060C
EVT_CHARACTERISTIC_VALUE_INDICATION = 0x060D
EVT_GATT_ERROR_NOTIFICATION = 0x060E
EVT_EXCHANGE_GATT_MTU_SIZE_RESPONSE = 0x060F
EVT_GATT_STOP_NOTIFICATION = 0x0610
EVT_GATT_TIMEOUT_NOTIFICATION = 0x0611

# GAP Events
EVT_GET_DEVICE_IO_CAPABILITIES_RESPONSE = 0x0680
EVT_GET_BLUETOOTH_DEVICE_ADDRESS_RESPONSE = 0x0681
EVT_GET_PEER_BLUETOOTH_DEVICE_ADDRESS_RESPONSE = 0x0682
EVT_GET_PEER_DEVICE_HANDLE_RESPONSE = 0x0683
EVT_CURRENT_CONNECTION_PARAMETERS_NOTIFICATION = 0x0684
EVT_GET_CONNECTION_PARAMETERS_RESPONSE = 0x0685
EVT_GET_SCAN_PARAMETERS_RESPONSE = 0x0686
EVT_GET_LOCAL_DEVICE_SECURITY_RESPONSE = 0x0687
EVT_GET_PEER_DEVICE_SECURITY_RESPONSE = 0x0688
EVT_GET_WHITE_LIST_RESPONSE = 0x0689
EVT_SCAN_PROGRESS_RESULT = 0x068A
EVT_GENERATE_BD_ADDR_RESPONSE = 0x068B
EVT_CURRENT_LOCAL_KEYS_RESPONSE = 0x068C
EVT_PASSKEY_ENTRY_REQUEST = 0x068D
EVT_PASSKEY_DISPLAY_REQUEST = 0x068E
EVT_ESTABLISH_CONNECTION_RESPONSE = 0x068F
EVT_CONNECTION_TERMINATED_NOTIFICATION = 0x0690
EVT_SCAN_STOPPED_NOTIFICATION = 0x0691
EVT_PAIRING_REQUEST_RECEIVED_NOTIFICATION = 0x0692
EVT_AUTHENTICATION_ERROR_NOTIFICATION = 0x0693
EVT_CONNECTION_CANCELLED_NOTIFICATION = 0x0694
EVT_GET_BONDED_DEVICES_BY_RANK_RESPONSE = 0x0695
EVT_UPDATE_CONNECTION_PARAMETERS_NOTIFICATION = 0x0696
EVT_GET_PEER_DEVICE_SECURITY_KEYS_RESPONSE = 0x0697
EVT_RESOLVE_AND_SET_PEER_BD_ADDRESS_RESPONSE = 0x0698
EVT_GET_LOCAL_DEVICE_SECURITY_KEYS_RESPONSE = 0x0699
EVT_GET_HOST_CHANNEL_MAP_RESPONSE = 0x069A
EVT_GET_DATA_LENGTH_RESPONSE = 0x069B
EVT_CONVERT_OCTET_TO_TIME_RESPONSE = 0x069C
EVT_DATA_LENGTH_CHANGED_NOTIFICATION = 0x069D
EVT_GET_RESOLVABLE_ADDRESS_RESPONSE = 0x069E
EVT_GET_RESOLVING_LIST_RESPONSE = 0x069F
EVT_ENHANCED_CONNECTION_COMPLETE = 0x06A0
EVT_DIRECT_ADV_SCAN_PROGRESS_RESULT = 0x06A1
EVT_GENERATE_SECURED_CONNECTION_OOB_DATA_RESPONSE = 0x06A2
EVT_NUMERIC_COMPARISON_REQUEST = 0x06A3
EVT_NEGOTIATED_PAIRING_PARAMETERS = 0x06A4
EVT_CBFC_CONNECTION_INDICATION = 0x0500
EVT_CBFC_CONNECTION_CONFIRMATION = 0x0501
EVT_CBFC_DISCONNECT_INDICATION = 0x0502
EVT_CBFC_DISCONNECT_CONFIRMATION = 0x0503
EVT_CBFC_DATA_RECEIVIED_NOTIFICATION = 0x0504
EVT_CBFC_RX_CREDIT_INDICATION = 0x0505
EVT_CBFC_TX_CREDIT_INDICATION = 0x0506
EVT_CBFC_DATA_WRITE_INDICATION = 0x0507

DESC_EVN = {
    EVT_COMMAND_STATUS: 'EVT_COMMAND_STATUS',
    EVT_COMMAND_COMPLETE: 'EVT_COMMAND_COMPLETE',
    EVT_GET_DEVICE_ID_RESPONSE: 'EVT_GET_DEVICE_ID_RESPONSE',
    EVT_GET_SUPPORTED_TOOL_VERSION_RESPONSE: 'EVT_GET_SUPPORTED_TOOL_VERSION_RESPONSE',
    EVT_GET_FIRMWARE_VERSION_RESPONSE: 'EVT_GET_FIRMWARE_VERSION_RESPONSE',
    EVT_GET_BLE_STACK_VERSION_RESPONSE: 'EVT_GET_BLE_STACK_VERSION_RESPONSE',
    EVT_REPORT_STACK_MISC_STATUS: 'EVT_REPORT_STACK_MISC_STATUS',
    EVT_GET_SUPPORTED_GAP_ROLES_RESPONSE: 'EVT_GET_SUPPORTED_GAP_ROLES_RESPONSE',
    EVT_GET_CURRENT_GAP_ROLE_RESPONSE: 'EVT_GET_CURRENT_GAP_ROLE_RESPONSE',
    EVT_GET_SUPPORTED_GATT_ROLES_RESPONSE: 'EVT_GET_SUPPORTED_GATT_ROLES_RESPONSE',
    EVT_GET_CURRENT_GATT_ROLE_RESPONSE: 'EVT_GET_CURRENT_GATT_ROLE_RESPONSE',
    EVT_GET_RSSI_RESPONSE: 'EVT_GET_RSSI_RESPONSE',
    EVT_GET_DEVICE_DESCRIPTION_RESPONSE: 'EVT_GET_DEVICE_DESCRIPTION_RESPONSE',
    EVT_GET_HARDWARE_VERSION_RESPONSE: 'EVT_GET_HARDWARE_VERSION_RESPONSE',
    EVT_GET_TX_POWER_RESPONSE: 'EVT_GET_TX_POWER_RESPONSE',

    HID_EP1_PACKET: 'HID_EP1_PACKET',
    HID_EP2_PACKET: 'HID_EP2_PACKET',
    AUDIO_REPORT: 'AUDIO_REPORT',
    AUDIO_CONTROL_STATUS: 'AUDIO_CONTROL_STATUS',
    AUDIO_SYNC_PACKET: 'AUDIO_SYNC_PACKET',
    AUDIO_RAW_DATA: 'AUDIO_RAW_DATA',

    EVT_DISCOVER_ALL_PRIMARY_SERVICES_RESULT_PROGRESS: 'EVT_DISCOVER_ALL_PRIMARY_SERVICES_RESULT_PROGRESS',
    EVT_DISCOVER_PRIMARY_SERVICES_BY_UUID_RESULT_PROGRESS: 'EVT_DISCOVER_PRIMARY_SERVICES_BY_UUID_RESULT_PROGRESS',
    EVT_FIND_INDLUDED_SERVICES_RESULT_PROGRESS: 'EVT_FIND_INDLUDED_SERVICES_RESULT_PROGRESS',
    EVT_DISCOVER_ALL_CHARACTERISTICS_RESULT_PROGRESS: 'EVT_DISCOVER_ALL_CHARACTERISTICS_RESULT_PROGRESS',
    EVT_DISCOVER_CHARACTERISTICS_BY_UUID_RESULT_PROGRESS: 'EVT_DISCOVER_CHARACTERISTICS_BY_UUID_RESULT_PROGRESS',
    EVT_DISCOVER_ALL_CHARACTERISTIC_DESCRIPTORS_RESULT_PROGRESS: 'EVT_DISCOVER_ALL_CHARACTERISTIC_DESCRIPTORS_RESULT_PROGRESS',
    EVT_READ_CHARACTERISTIC_VALUE_RESPONSE: 'EVT_READ_CHARACTERISTIC_VALUE_RESPONSE',
    EVT_READ_USING_CHARACTERISTIC_UUID_RESPONSE: 'EVT_READ_USING_CHARACTERISTIC_UUID_RESPONSE',
    EVT_READ_LONG_CHARACTERISTIC_VALUE_RESPONSE: 'EVT_READ_LONG_CHARACTERISTIC_VALUE_RESPONSE',
    EVT_READ_MULTIPLE_CHARACTERISTIC_VALUES_RESPONSE: 'EVT_READ_MULTIPLE_CHARACTERISTIC_VALUES_RESPONSE',
    EVT_READ_CHARACTERISTIC_DESCRIPTOR_RESPONSE: 'EVT_READ_CHARACTERISTIC_DESCRIPTOR_RESPONSE',
    EVT_READ_LONG_CHARACTERISTIC_DESCRIPTOR_RESPONSE: 'EVT_READ_LONG_CHARACTERISTIC_DESCRIPTOR_RESPONSE',
    EVT_CHARACTERISTIC_VALUE_NOTIFICATION: 'EVT_CHARACTERISTIC_VALUE_NOTIFICATION',
    EVT_CHARACTERISTIC_VALUE_INDICATION: 'EVT_CHARACTERISTIC_VALUE_INDICATION',
    EVT_GATT_ERROR_NOTIFICATION: 'EVT_GATT_ERROR_NOTIFICATION',
    EVT_EXCHANGE_GATT_MTU_SIZE_RESPONSE: 'EVT_EXCHANGE_GATT_MTU_SIZE_RESPONSE',
    EVT_GATT_STOP_NOTIFICATION: 'EVT_GATT_STOP_NOTIFICATION',
    EVT_GATT_TIMEOUT_NOTIFICATION: 'EVT_GATT_TIMEOUT_NOTIFICATION',

    EVT_GET_DEVICE_IO_CAPABILITIES_RESPONSE: 'EVT_GET_DEVICE_IO_CAPABILITIES_RESPONSE',
    EVT_GET_BLUETOOTH_DEVICE_ADDRESS_RESPONSE: 'EVT_GET_BLUETOOTH_DEVICE_ADDRESS_RESPONSE',
    EVT_GET_PEER_BLUETOOTH_DEVICE_ADDRESS_RESPONSE: 'EVT_GET_PEER_BLUETOOTH_DEVICE_ADDRESS_RESPONSE',
    EVT_GET_PEER_DEVICE_HANDLE_RESPONSE: 'EVT_GET_PEER_DEVICE_HANDLE_RESPONSE',
    EVT_CURRENT_CONNECTION_PARAMETERS_NOTIFICATION: 'EVT_CURRENT_CONNECTION_PARAMETERS_NOTIFICATION',
    EVT_GET_CONNECTION_PARAMETERS_RESPONSE: 'EVT_GET_CONNECTION_PARAMETERS_RESPONSE',
    EVT_GET_SCAN_PARAMETERS_RESPONSE: 'EVT_GET_SCAN_PARAMETERS_RESPONSE',
    EVT_GET_LOCAL_DEVICE_SECURITY_RESPONSE: 'EVT_GET_LOCAL_DEVICE_SECURITY_RESPONSE',
    EVT_GET_PEER_DEVICE_SECURITY_RESPONSE: 'EVT_GET_PEER_DEVICE_SECURITY_RESPONSE',
    EVT_GET_WHITE_LIST_RESPONSE: 'EVT_GET_WHITE_LIST_RESPONSE',
    EVT_SCAN_PROGRESS_RESULT: 'EVT_SCAN_PROGRESS_RESULT',
    EVT_GENERATE_BD_ADDR_RESPONSE: 'EVT_GENERATE_BD_ADDR_RESPONSE',
    EVT_CURRENT_LOCAL_KEYS_RESPONSE: 'EVT_CURRENT_LOCAL_KEYS_RESPONSE',
    EVT_PASSKEY_ENTRY_REQUEST: 'EVT_PASSKEY_ENTRY_REQUEST',
    EVT_PASSKEY_DISPLAY_REQUEST: 'EVT_PASSKEY_DISPLAY_REQUEST',
    EVT_ESTABLISH_CONNECTION_RESPONSE: 'EVT_ESTABLISH_CONNECTION_RESPONSE',
    EVT_CONNECTION_TERMINATED_NOTIFICATION: 'EVT_CONNECTION_TERMINATED_NOTIFICATION',
    EVT_SCAN_STOPPED_NOTIFICATION: 'EVT_SCAN_STOPPED_NOTIFICATION',
    EVT_PAIRING_REQUEST_RECEIVED_NOTIFICATION: 'EVT_PAIRING_REQUEST_RECEIVED_NOTIFICATION',
    EVT_AUTHENTICATION_ERROR_NOTIFICATION: 'EVT_AUTHENTICATION_ERROR_NOTIFICATION',
    EVT_CONNECTION_CANCELLED_NOTIFICATION: 'EVT_CONNECTION_CANCELLED_NOTIFICATION',
    EVT_GET_BONDED_DEVICES_BY_RANK_RESPONSE: 'EVT_GET_BONDED_DEVICES_BY_RANK_RESPONSE',
    EVT_UPDATE_CONNECTION_PARAMETERS_NOTIFICATION: 'EVT_UPDATE_CONNECTION_PARAMETERS_NOTIFICATION',
    EVT_GET_PEER_DEVICE_SECURITY_KEYS_RESPONSE: 'EVT_GET_PEER_DEVICE_SECURITY_KEYS_RESPONSE',
    EVT_RESOLVE_AND_SET_PEER_BD_ADDRESS_RESPONSE: 'EVT_RESOLVE_AND_SET_PEER_BD_ADDRESS_RESPONSE',
    EVT_GET_LOCAL_DEVICE_SECURITY_KEYS_RESPONSE: 'EVT_GET_LOCAL_DEVICE_SECURITY_KEYS_RESPONSE',
    EVT_GET_HOST_CHANNEL_MAP_RESPONSE: 'EVT_GET_HOST_CHANNEL_MAP_RESPONSE',
    EVT_GET_DATA_LENGTH_RESPONSE: 'EVT_GET_DATA_LENGTH_RESPONSE',
    EVT_CONVERT_OCTET_TO_TIME_RESPONSE: 'EVT_CONVERT_OCTET_TO_TIME_RESPONSE',
    EVT_DATA_LENGTH_CHANGED_NOTIFICATION: 'EVT_DATA_LENGTH_CHANGED_NOTIFICATION',
    EVT_GET_RESOLVABLE_ADDRESS_RESPONSE: 'EVT_GET_RESOLVABLE_ADDRESS_RESPONSE',
    EVT_GET_RESOLVING_LIST_RESPONSE: 'EVT_GET_RESOLVING_LIST_RESPONSE',
    EVT_ENHANCED_CONNECTION_COMPLETE: 'EVT_ENHANCED_CONNECTION_COMPLETE',
    EVT_DIRECT_ADV_SCAN_PROGRESS_RESULT: 'EVT_DIRECT_ADV_SCAN_PROGRESS_RESULT',
    EVT_GENERATE_SECURED_CONNECTION_OOB_DATA_RESPONSE: 'EVT_GENERATE_SECURED_CONNECTION_OOB_DATA_RESPONSE',
    EVT_NUMERIC_COMPARISON_REQUEST: 'EVT_NUMERIC_COMPARISON_REQUEST',
    EVT_NEGOTIATED_PAIRING_PARAMETERS: 'EVT_NEGOTIATED_PAIRING_PARAMETERS',

    EVT_CBFC_CONNECTION_INDICATION: 'EVT_CBFC_CONNECTION_INDICATION',
    EVT_CBFC_CONNECTION_CONFIRMATION: 'EVT_CBFC_CONNECTION_CONFIRMATION',
    EVT_CBFC_DISCONNECT_INDICATION: 'EVT_CBFC_DISCONNECT_INDICATION',
    EVT_CBFC_DISCONNECT_CONFIRMATION: 'EVT_CBFC_DISCONNECT_CONFIRMATION',
    EVT_CBFC_DATA_RECEIVIED_NOTIFICATION: 'EVT_CBFC_DATA_RECEIVIED_NOTIFICATION',
    EVT_CBFC_RX_CREDIT_INDICATION: 'EVT_CBFC_RX_CREDIT_INDICATION',
    EVT_CBFC_TX_CREDIT_INDICATION: 'EVT_CBFC_TX_CREDIT_INDICATION',
    EVT_CBFC_DATA_WRITE_INDICATION: 'EVT_CBFC_DATA_WRITE_INDICATION',
}

# CySmt_protocol.c
# ====================================================================

GRUPPO_0 = (
    'Cmd_Get_Device_Id_Api',
    'Cmd_Get_Supported_Tool_Ver_Api',
    'Cmd_Get_Firmware_Version_Api',
    'Cmd_Get_Supported_Gap_Roles_Api',
    'Cmd_Get_Current_Gap_Role_Api',
    'Cmd_Get_Supported_Gatt_Roles_Api',
    'Cmd_Get_Current_Gatt_Role_Api',
    'Cmd_Init_Ble_Stack_Api',
    'Cmd_Tool_Disconnected_Api',
    'Cmd_Host_Timed_Out_Api',
    'Cmd_Get_Device_Descriptor_Info',
    'Cmd_Get_Hardware_Version_Api',
    'Cmd_Get_Ble_Stack_Version_Api',
    'Cmd_Get_Rssi_Api',
    'Cmd_Get_TxPowerLevel_Api',
    'Cmd_Set_TxPowerLevel_Api',
    'Cmd_Set_HostChannelClassification_Api'
)
GRUPPO_2 = {
    'Cmd_Register_PSM_Api',
    'Cmd_Unregister_PSM_Api',
    'Cmd_CBFC_SendConnectionReq_Api',
    'Cmd_CBFC_SendConnectionResp_Api',
    'Cmd_CBFC_SendFlowControlCredit_Api',
    'Cmd_CBFC_SendData_Api',
    'Cmd_CBFC_SendDisconnectReq_Api'
}
GRUPPO_4 = (
    'Cmd_Discover_All_Primary_Services_Api',
    'Cmd_Discover_Primary_Services_By_Uuid_Api',
    'Cmd_Find_Included_Services_Api',
    'Cmd_Discover_All_Characteristics_Api',
    'Cmd_Discover_Characteristics_By_Uuid_Api',
    'Cmd_Discover_All_Characteristic_Descriptors_Api',
    'Cmd_Read_Characteristic_Value_Api',
    'Cmd_Read_Using_Characteristic_Uuid_Api',
    'Cmd_Read_Long_Characteristic_Values_Api',
    'Cmd_Read_Multiple_Characteristic_Values_Api',
    'Cmd_Characteristic_Value_Write_Without_Response_Api',
    'Cmd_Write_Characteristic_Value_Api',
    'Cmd_Write_Long_Characteristic_Value_Api',
    'Cmd_Reliable_Characteristic_Value_Writes_Api',
    'Cmd_Read_Characteristic_Descriptor_Api',
    'Cmd_Read_Long_Characteristic_Descriptor_Api',
    'Cmd_Write_Characteristic_Descriptor_Api',
    'Cmd_Write_Long_Characteristic_Descriptor_Api',
    'Cmd_Exchange_GATT_MTU_Size_Api',
    'Cmd_GATT_Stop_Api',
    'Cmd_Signed_Write_Without_Response_Api',
    'Cmd_Execute_Write_Request_Api'
)
GRUPPO_5 = (
    'Cmd_Set_Device_Io_Capabilities_Api',
    'Cmd_Get_Device_Io_Capabilities_Api',
    'Cmd_Get_Bluetooth_Device_Address_Api',
    'Cmd_Set_Bluetooth_Device_Address_Api',
    'Cmd_Get_Peer_Bluetooth_Device_Address_Api',
    'Cmd_Get_Peer_Device_Handle_Api',
    'Cmd_GenerateBd_Addr_Api',
    'Cmd_Set_Oob_Data_Api',
    'Cmd_Get_Connection_Parameters_Api',
    'Cmd_Set_Connection_Parameters_Api',
    'Cmd_Get_Scan_Parameters_Api',
    'Cmd_Set_Scan_Parameters_Api',
    'Cmd_Get_Local_Device_Security_Api',
    'Cmd_Set_Local_Device_Security_Api',
    'Cmd_Get_Peer_Device_Security_Api',
    'Cmd_Get_White_List_Api',
    'Cmd_Add_Device_To_White_List_Api',
    'Cmd_Remove_Device_From_White_List_Api',
    'Cmd_Clear_White_List_Api',
    'Cmd_Start_Scan_Api',
    'Cmd_Stop_Scan_Api',
    'Cmd_Generate_Set_Keys_Api',
    'Cmd_Set_Authentication_Keys_Api',
    'Cmd_Establish_Connection_Api',
    'Cmd_Terminate_Connection_Api',
    'Cmd_Initiate_Pairing_Request_Api',
    'Cmd_Set_Identiry_Addr_Api',
    'Cmd_Pairing_PassKey_Api',
    'Cmd_Update_Connection_Params_Api',
    'Cmd_Cancle_Connection_Api',
    'Cmd_Get_Bonded_Devices_By_Rank_Api',
    'Cmd_UpdateConnectionParam_Resp_Api',
    'Cmd_Get_PeerDevice_SecurityKeys_Api',
    'Cmd_Resolve_Set_Peer_Addr_Api',
    'Cmd_Get_LocalDevSecurityKeys_Api',
    'Cmd_Get_HostChannelMap_Api',
    'Cmd_Remove_Device_From_Bond_List_Api',
    'Cmd_Clear_Bond_List_Api',
    'Cmd_Set_Conn_Data_Len_Api',
    'Cmd_Get_Default_Data_Len_Api',
    'Cmd_Set_Default_Data_Len_Api',
    'Cmd_Convert_OctetToTime_Api',
    'Cmd_Get_Resolving_List_Api',
    'Cmd_Add_Device_To_Resolving_List_Api',
    'Cmd_Remove_Device_From_Resolving_List_Api',
    'Cmd_Clear_Resolving_List_Api',
    'Cmd_Get_Peer_Resolvable_Addr_Api',
    'Cmd_Get_Local_Resolvable_Addr_Api',
    'Cmd_Set_Resolvable_Addr_Timeout_Api',
    'Cmd_Addr_Resolution_Control_Api',
    'Cmd_GenerateLocalP256PublicKey_Api',
    'Cmd_SendSecuredConnectionKeyPress_Api',
    'Cmd_GenerateSecuredConnectionOobData_Api',
)
