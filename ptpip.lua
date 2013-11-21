-- Wireshark dissector for Picture Transfer Protocol (PTP)
-- See: http://www.gphoto.org/doc/ptpip.php

local ptp_proto = Proto("PTP-IP", "Picture Transfer Protocol/IP")

ptp_proto.prefs["tcp_port"] = Pref.uint("TCP Port", 15740, "TCP Port for PTP/IP")


local ptp_container_types = {
    [1]="Init Command Request",
    [2]="Init Command ACK",
    [3]="Init Event Request",
    [4]="Init Event ACK",
    [5]="Init Fail",
    [6]="Operation Request",
    [7]="Operation Response",
    [8]="Event",
    [9]="Start Data",
    [10]="Data",
    [11]="Cancel Data",
    [12]="End Data",
    [13]="Probe Request",
    [14]="Probe Response"
}

local ptp_operation_codes = {
    [0x1001]="GetDeviceInfo",
    [0x1002]="OpenSession",
    [0x1004]="GetStorageIDs",
    [0x1005]="GetStorageInfo",
    [0x1006]="GetNumObjects",
    [0x1007]="GetObjectHandles",
    [0x1008]="GetObjectInfo",
    [0x1009]="GetObject",
    [0x100a]="GetThumb",
    [0x100b]="DeleteObject",
    [0x100c]="SendObjectInfo",
    [0x100d]="SendObject",
    [0x100e]="InitiateCapture",
    [0x100f]="FormatStore",
    [0x1010]="ResetDevice",
    [0x1011]="SelfTest",
    [0x1012]="SetObjectProtection",
    [0x1013]="PowerDown",
    [0x1014]="GetDevicePropDesc",
    [0x1015]="GetDevicePropValue",
    [0x1016]="SetDevicePropValue",
    [0x1017]="ResetDevicePropValue",
    [0x1018]="TerminateOpenCapture",
    [0x1019]="MoveObject",
    [0x101a]="CopyObject",
    [0x101b]="GetPartialObject",
    [0x101c]="InitiateOpenCapture",
    [0x101d]="StartEnumHandles",
    [0x101e]="EnumHandles",
    [0x101f]="StopEnumHandles",
    [0x1020]="GetVendorExtensionMaps",
    [0x1021]="GetVendorDeviceInfo",
    [0x1022]="GetResizedImageObject",
    [0x1023]="GetFilesystemManifest",
    [0x1024]="GetStreamInfo",
    [0x1025]="GetStream",
    [0x9000]="EXTENSION",
    [0x9801]="GetObjectPropsSupported",
    [0x9802]="GetObjectPropDesc"
}

local ptp_response_codes = {
    [0x2001]="OK",
    [0x2002]="GeneralError",
    [0x2003]="SessionNotOpen",
    [0x2004]="InvalidTransactionID",
    [0x2005]="OperationNotSupported",
    [0x2006]="ParameterNotSupported",
    [0x2007]="IncompleteTransfer",
    [0x2008]="InvalidStorageId",
    [0x2009]="InvalidObjectHandle",
    [0x200a]="DevicePropNotSupported",
    [0x200b]="InvalidObjectFormatCode",
    [0x200c]="StoreFull",
    [0x200d]="ObjectWriteProtected",
    [0x200e]="StoreReadOnly",
    [0x200f]="AccessDenied",
    [0x2010]="NoThumbnailPresent",
    [0x2011]="SelfTestFailed",
    [0x2012]="PartialDeletion",
    [0x2013]="StoreNotAvailable",
    [0x2014]="SpecificationByFormatUnsupported",
    [0x2015]="NoValidObjectInfo",
    [0x2016]="InvalidCodeFormat",
    [0x2017]="UnknownVendorCode",
    [0x2018]="CaptureAlreadyTerminated",
    [0x2019]="DeviceBusy",
    [0x201a]="InvalidParentObject",
    [0x201b]="InvalidDevicePropFormat",
    [0x201c]="InvalidDevicePropValue",
    [0x201d]="InvalidParameter",
    [0x201e]="SessionAlreadyOpened",
    [0x201f]="TransactionCanceled",
    [0x2020]="SpecificationOfDestinationUnsupported",
    [0x2021]="InvalidEnumHandle",
    [0x2022]="NoStreamEnabled",
    [0x2023]="InvalidDataSet"
}

local ptp_event_codes = {
    [0x4001]="CancelTransaction",
    [0x4002]="ObjectAdded",
    [0x4003]="ObjectRemoved",
    [0x4004]="StoreAdded",
    [0x4005]="StoreRemoved",
    [0x4006]="DevicePropChanged",
    [0x4007]="ObjectInfoChanged",
    [0x4008]="DeviceInfoChanged",
    [0x4009]="RequestObjectTransfer",
    [0x400a]="StoreFull",
    [0x400b]="DeviceReset",
    [0x400c]="StorageInfoChanged",
    [0x400d]="CaptureComplete",
    [0x400e]="UnreportedStatus"
}

local ptp_device_properties = {
    [0x5001]="BatteryLevel",
    [0x5002]="FunctionalMode",
    [0x5003]="ImageSize",
    [0x5004]="CompressionSetting",
    [0x5005]="WhiteBalance",
    [0x5006]="RGBGain",
    [0x5007]="FNumber",
    [0x5008]="FocalLength",
    [0x5009]="FocusDistance",
    [0x500a]="FocusMode",
    [0x500b]="ExposureMeteringMode",
    [0x500c]="FlashMode",
    [0x500d]="ExposureTime",
    [0x500e]="ExposureProgramMode",
    [0x500f]="ExposureIndex",
    [0x5010]="ExposureBiasCompensation",
    [0x5011]="DateTime",
    [0x5012]="CaptureDelay",
    [0x5013]="StillCaptureMode",
    [0x5014]="Contrast",
    [0x5015]="Sharpness",
    [0x5016]="DigitalZoom",
    [0x5017]="EffectMode",
    [0x5018]="BurstNumber",
    [0x5019]="BurstInterval",
    [0x501a]="TimelapseNumber",
    [0x501b]="TimelapseInterval",
    [0x501c]="FocusMeteringMode",
    [0x501d]="UploadURL",
    [0x501e]="Artist",
    [0x501f]="CopyrightInfo",
    [0x5020]="SupportedStreams",
    [0x5021]="EnabledStreams",
    [0x5022]="VideoFormat",
    [0x5023]="VideoResolution",
    [0x5024]="VideoQuality",
    [0x5025]="VideoFrameRate",
    [0x5026]="VideoContrast",
    [0x5027]="VideoBrightness",
    [0x5028]="AudioFormat",
    [0x5029]="AudioBitrate",
    [0x502a]="AudioSamplingRate",
    [0x502b]="AudioBitPerSample",
    [0x502c]="AudioVolume"    
}

local PTP_OC_GETDEVICEINFO = 0x1001
local PTP_OC_GETSTORAGEIDS = 0x1004
local PTP_OC_GETOBJECTHANDLES = 0x1007
local PTP_OC_GETDEVICEPROPDESC = 0x1014
local PTP_OC_GETDEVICEPROPVALUE = 0x1015
local PTP_OC_SETDEVICEPROPVALUE = 0x1016

local fields = ptp_proto.fields
fields.container_length = ProtoField.uint32("ptp.container.length", "Container Length", base.DEC)
fields.container_type = ProtoField.uint32("ptp.container.type", "Container Type", nil, ptp_container_types)

fields.operation_code = ProtoField.uint16("ptp.operation.code", "Operation Code", base.HEX, ptp_operation_codes)
fields.response_code = ProtoField.uint16("ptp.response.code", "Response Code", base.HEX, ptp_response_codes)
fields.event_code = ProtoField.uint16("ptp.event.code", "Event Code", base.HEX, ptp_event_codes)
fields.failure_code = ProtoField.uint16("ptp.failure.code", "Failure Code", base.HEX)

fields.transaction_id = ProtoField.uint32("ptp.transaction.id", "Transaction ID", base.DEC)
fields.payload = ProtoField.bytes("ptp.payload", "Payload")

fields.intiator_guid = ProtoField.guid("ptp.initiator.guid", "Initiator GUID")
fields.intiator_name = ProtoField.string("ptp.initiator.name", "Initiator Friendly Name")
fields.intiator_proto_version = ProtoField.uint32("ptp.initiator.protocol_version", "Initiator Protocol Version", base.HEX)

fields.session_id = ProtoField.uint32("ptp.session.id", "Connection Number")
fields.responder_guid = ProtoField.guid("ptp.responder.guid", "Responder GUID")
fields.responder_name = ProtoField.string("ptp.responder.name", "Responder Friendly Name")
fields.responder_proto_version = ProtoField.uint32("ptp.responder.protocol_version", "Initiator Protocol Version", base.HEX)

fields.dataphase = ProtoField.uint32("ptp.dataphase", "Dataphase", base.HEX)
fields.data_length = ProtoField.uint64("ptp.data_length", "Date Length")

fields.device_property = ProtoField.uint32("ptp.device.property", "Device Property", base.HEX, ptp_device_properties)


local ptp_container_dispatch = {
    -- Init Command Request
    [1] = function (buffer, subtree)
        local name = buffer(16, buffer:len() - 16 - 4):le_ustringz()

        subtree:add(fields.intiator_guid, buffer(0, 16))
        subtree:add(fields.intiator_name, name)
        subtree:add(fields.intiator_proto_version, buffer(buffer:len() - 4, 4):le_uint())
        return name
    end,

    -- Init Command ACK
    [2] = function (buffer, subtree)
        local name = buffer(20, buffer:len() - 20 - 4):le_ustringz()

        subtree:add(fields.session_id, buffer(0, 4):le_uint())
        subtree:add(fields.responder_guid, buffer(4, 16))
        subtree:add(fields.responder_name, name)
        subtree:add(fields.responder_proto_version, buffer(buffer:len() - 4, 4):le_uint())
        return name
    end,

    -- Init Event Request
    [3] = function (buffer, subtree)
        subtree:add(fields.session_id, buffer(0, 4):le_uint())
    end,

    -- Init Event ACK
    [4] = function (buffer, subtree)
    end,

    -- Init Fail
    [5] = function (buffer, subtree)
        local failure_code = buffer(6, 4):le_uint()
        subtree:add(fields.failure_code, failure_code)
        return string.format("%04X", failure_code)
    end,

    -- Operation Request
    [6] = function (buffer, subtree)
        local op_code = buffer(4, 2):le_uint()
        local transaction_id = buffer(6, 4):le_uint()

        subtree:add(fields.dataphase, buffer(0, 4):le_uint())
        subtree:add(fields.operation_code, op_code)
        subtree:add(fields.transaction_id, transaction_id)

        if op_code == PTP_OC_GETDEVICEPROPDESC or op_code == PTP_OC_GETDEVICEPROPVALUE or op_code == PTP_OC_SETDEVICEPROPVALUE then
            subtree:add(fields.device_property, buffer(10, 4):le_uint())
        end

        if ptp_operation_codes[op_code] ~= nil then
            return ptp_operation_codes[op_code] .. " (Transaction #" .. transaction_id .. ")"
        else
            return string.format("%04X (Transaction #%d)", op_code, transaction_id)
        end
    end,

    -- Operation Response
    [7] = function (buffer, subtree)
        local response_code = buffer(0, 2):le_uint()
        local transaction_id = buffer(2, 4):le_uint()

        subtree:add(fields.response_code, response_code)
        subtree:add(fields.transaction_id, transaction_id)

        if ptp_response_codes[response_code] ~= nil then
            return ptp_response_codes[response_code] .. " (Transaction #" .. transaction_id .. ")"
        else
            return string.format("%04X (Transaction #%d)", response_code, transaction_id)
        end
    end,

    -- Event
    [8] = function (buffer, subtree)
        local event_code = buffer(0, 2):le_uint()
        local transaction_id = buffer(2, 4):le_uint()

        subtree:add(fields.event_code, event_code)
        subtree:add(fields.transaction_id, transaction_id)

        if ptp_event_codes[event_code] ~= nil then
            return ptp_event_codes[event_code] .. " (Transaction #" .. transaction_id .. ")"
        else
            return string.format("%04X (Transaction #%d)", event_code, transaction_id)
        end
    end,

    -- Start Data
    [9] = function (buffer, subtree)
        local transaction_id = buffer(0, 4):le_uint()
        subtree:add(fields.transaction_id, transaction_id)
        subtree:add(fields.data_length, buffer(4, 8):le_uint64())
        return "Transaction #" .. transaction_id
    end,

    -- Data
    [10] = function (buffer, subtree)
        local transaction_id = buffer(0, 4):le_uint()
        subtree:add(fields.transaction_id, transaction_id)
        subtree:add(fields.payload, buffer(4))
        return "Transaction #" .. transaction_id
    end,

    -- End Data
    [11] = function (buffer, subtree)
        local transaction_id = buffer(0, 4):le_uint()
        subtree:add(fields.transaction_id, transaction_id)
        subtree:add(fields.payload, buffer(4))
        return "Transaction #" .. transaction_id
    end,

    -- Cancel
    [12] = function (buffer, subtree)
        local transaction_id = buffer(0, 4):le_uint()
        subtree:add(fields.transaction_id, transaction_id)
        return "Transaction #" .. transaction_id
    end,

}

local CONTAINER_HEADER_LENGTH = 8

-- Initialization routine
function ptp_proto.init()
    local tcp_table = DissectorTable.get("tcp.port")
    tcp_table:add(ptp_proto.prefs["tcp_port"], ptp_proto)
end

-- create a function to dissect it
function ptp_proto.dissector(buffer, pinfo, tree)
    local remaining = buffer:len() - CONTAINER_HEADER_LENGTH
    if remaining < 0 then
        pinfo.desegment_len = -remaining
        return remaining
    end

    local ptp_length = buffer(0, 4):le_uint()
    remaining = buffer:len() - ptp_length
    if remaining < 0 then
        pinfo.desegment_len = -remaining
        return remaining
    end

    pinfo.cols.protocol = "PTP/IP"

    local ptp_type = buffer(4, 4):le_uint()

    local subtree = tree:add(ptp_proto, buffer(), "Picture Transfer Protocol")
    subtree:add(fields.container_length, ptp_length)
    subtree = subtree:add(fields.container_type, ptp_type)

    pinfo.cols.info = ptp_container_types[ptp_type]

    local dispatch = ptp_container_dispatch[ptp_type]
    if dispatch ~= nil then
        local infos = dispatch(buffer(CONTAINER_HEADER_LENGTH, ptp_length - CONTAINER_HEADER_LENGTH), subtree)
        if infos ~= nil then
            pinfo.cols.info:append(": " .. infos)
        end
    elseif ptp_length > CONTAINER_HEADER_LENGTH then
        subtree:add(fields.payload, buffer(CONTAINER_HEADER_LENGTH, ptp_length - CONTAINER_HEADER_LENGTH))
    end

    return ptp_length
end

