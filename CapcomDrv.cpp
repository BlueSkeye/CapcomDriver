#include <Ntddk.h>
#include <intrin.h>

wchar_t deletedDosDeviceNameBuffer[0x20];
wchar_t dosDeviceNameBuffer[0x20];
wchar_t deviceNameBuffer[0x40];
wchar_t ObfuscatedDeviceName[] { 0x87, 0xEA, 0xFD, 0x9A, 0x4B, 0x73, 0x54, 0xA4, 0x5C, 0x8F, 0x00 };

typedef PVOID(__stdcall *pfnMmGetSystemRoutineAddress)(_In_ PUNICODE_STRING SystemRoutineName);

typedef void(*pfnSMEPDisabledCallback)(pfnMmGetSystemRoutineAddress pMmGetSystemRoutineAddress,
	int ioctlCode, int unknown2, int unknown4);

typedef struct _CAPCOM_IOCTL {
	unsigned char cbLength;
	unsigned long Unknown1;
	unsigned long Unknown2;
	unsigned long Unknown3;
	unsigned long Unknown4;
	unsigned long Unknown5;
	unsigned long IoctlCode;
} CAPCOM_IOCTL, *PCAPCOM_IOCTL;

typedef struct _SMEPARGS
{
	__int64 savedCR4;
	pfnSMEPDisabledCallback Callback;
	pfnMmGetSystemRoutineAddress pMmGetSystemRoutineAddress;
} SMEPARGS, *PSMEPARGS;

static void DisableSMEP(PSMEPARGS args);
static void EnableSMEP(PSMEPARGS args);

wchar_t *DeobfuscateAndAppend(wchar_t *into, wchar_t *obfuscatedValue)
{
	wchar_t localBuffer[0x40];
	unsigned short rotatingKey = 0x5555;
	unsigned int seed = 0;

	wcscpy(localBuffer, obfuscatedValue);
	for (int localBufferIndex = 0; localBuffer[localBufferIndex]; localBufferIndex++) {
		rotatingKey = (rotatingKey << 2) + (unsigned short)(seed);
		unsigned int input = (localBuffer[localBufferIndex] >> 6);
		if (3 < input) { break; }
		unsigned short fork = (((unsigned char)(localBuffer[localBufferIndex]) ^ (unsigned char)(rotatingKey)) -
			(unsigned char)(seed)-(unsigned char)(input)) & 0x3F;
		wchar_t transformed = 0;
		if (10 > fork) {
			transformed = fork + 48;
		}
		else {
			if (36 > fork) {
				transformed = fork + 55;
			}
			else if (62 > fork) {
				transformed = fork + 61;
			}
		}
		if (62 == fork) {
			transformed = 46;
		}
		if (0 == transformed) { break; }
		localBuffer[localBufferIndex] = transformed;
		seed++;
	}
	return wcscat(into, localBuffer);
}

VOID Unload(_In_ struct _DRIVER_OBJECT *DriverObject)
{
	UNICODE_STRING symbolicLinkName;
	PDEVICE_OBJECT device = DriverObject->DeviceObject;

	wcscpy(deletedDosDeviceNameBuffer, L"\\DosDevices\\");
	RtlInitUnicodeString(&symbolicLinkName,
		DeobfuscateAndAppend(deletedDosDeviceNameBuffer, ObfuscatedDeviceName));
	IoDeleteSymbolicLink(&symbolicLinkName);
	IoDeleteDevice(device);
	return;
}

NTSTATUS CreateOrClose(_In_ struct _DEVICE_OBJECT *DeviceObject, _Inout_ struct _IRP *Irp)
{
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	switch(*(static_cast<unsigned char*>(Irp->Tail.Apc.SystemArgument1))) {
	case IRP_MJ_CREATE:
	case IRP_MJ_CLOSE:
		IofCompleteRequest(Irp, 0);
		break;
	default:
		Irp->IoStatus.Status = 0xC0000002;
		break;
	}
	return Irp->IoStatus.Status;
}

bool InvokeWithSMEPDisabled(pfnSMEPDisabledCallback callback,
	int ioctlCode, int unknown2, int unknown4)
{
	SMEPARGS smepArgs;

	// Maybe intended to prevent wide use of the driver.
	if (callback != ((pfnSMEPDisabledCallback*)callback)[-1]) {
		return false;
	}
	smepArgs.savedCR4 = 0;
	smepArgs.Callback = callback;
	smepArgs.pMmGetSystemRoutineAddress = MmGetSystemRoutineAddress;
	DisableSMEP(&smepArgs);
	smepArgs.Callback(smepArgs.pMmGetSystemRoutineAddress,
		ioctlCode, unknown2, unknown4);
	EnableSMEP(&smepArgs);
	return true;
}

NTSTATUS CapcomDispatchDeviceControl(_In_ struct _DEVICE_OBJECT *DeviceObject, _Inout_ struct _IRP *Irp)
{
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	PCAPCOM_IOCTL ioctl = static_cast<PCAPCOM_IOCTL>(Irp->Tail.Apc.SystemArgument1);

	if (14 != (ioctl->cbLength)) {
		Irp->IoStatus.Status = 0xC0000002;
	}
	else {
		int expected1 = 0; // Maybe a pointer size in bytes.
		int expected2; // maybe a data size in bytes
		switch (ioctl->IoctlCode) {
		case 0xAA012044:
			expected1 = 4;
			expected2 = 4;
			break;
		case 0xAA013044:
			expected1 = 8;
			expected2 = 4;
			break;
		default:
			break;
		}
		if ((expected1 == ioctl->Unknown4) && (expected2 == ioctl->Unknown2)) {
			bool resultData;
			// TODO : The first parameter is actually a 32 bits or 64 bits
			// pointer depending on the IOCTL code.
			switch (ioctl->IoctlCode) {
			case 0xAA012044: // 32 bits mode
				resultData = InvokeWithSMEPDisabled(
					*(static_cast<pfnSMEPDisabledCallback*>(Irp->AssociatedIrp.SystemBuffer)),
					ioctl->IoctlCode, ioctl->Unknown2, ioctl->Unknown4);
				break;
			case 0xAA013044: // 64 bits mode
				resultData = InvokeWithSMEPDisabled(
					*(static_cast<pfnSMEPDisabledCallback*>(Irp->AssociatedIrp.SystemBuffer)),
					ioctl->IoctlCode, ioctl->Unknown2, ioctl->Unknown4);
				break;
			default:
				break;
			}
			*(static_cast<bool*>(Irp->AssociatedIrp.SystemBuffer)) = resultData;
			Irp->IoStatus.Information = ioctl->IoctlCode;
		}
		else {
			Irp->IoStatus.Status = 0xC000000D;
		}
	}
	IofCompleteRequest(Irp, 0);
	return Irp->IoStatus.Status;
}

NTSTATUS DriverEntry(_In_ struct _DRIVER_OBJECT *DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	UNICODE_STRING name;
	UNICODE_STRING SymbolicLinkName;
	PDEVICE_OBJECT newDevice;
	NTSTATUS result;

	wcscpy(deviceNameBuffer, L"\\Device\\");
	RtlInitUnicodeString(&name,
		DeobfuscateAndAppend(deviceNameBuffer, ObfuscatedDeviceName));
	result = IoCreateDevice(DriverObject, 0, &name, 0xAA01, 0, FALSE, &newDevice);
	if (0 > result) {
		return result;
	}
	wcscpy(dosDeviceNameBuffer, L"\\DosDevices\\");
	RtlInitUnicodeString(&SymbolicLinkName,
		DeobfuscateAndAppend(dosDeviceNameBuffer, ObfuscatedDeviceName));
	result = IoCreateSymbolicLink(&SymbolicLinkName, &name);
	if (0 > result) {
		IoDeleteDevice(newDevice);
		return result;
	}
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateOrClose;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateOrClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = CapcomDispatchDeviceControl;
	DriverObject->DriverUnload = Unload;
	return result;
}

// See https://www.ncsi.com/nsatc11/presentations/wednesday/emerging_technologies/fischer.pdf
void DisableSMEP(PSMEPARGS args)
{
	_disable();
	__writecr4(
		(args->savedCR4 = __readcr4()) & ~(0x100000));
	return;
}

void EnableSMEP(PSMEPARGS args)
{
	__writecr4(args->savedCR4);
	_enable();
	return;
}
