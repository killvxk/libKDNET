#include <stdlib.h>
#include <malloc.h>
#include <stdio.h>
#include <stdint.h>
#include <memory.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "sha256.h"
#include "hmacsha256.h"
#include "aes.h"
#include "cbc_aes.h"
#include "kd.h"

#include "test_pkt.h"

#define DEBUG 1

//TODO: key "1.1.1.1" is the only supported key...
BYTE controlKey[32] = {
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
	
BYTE hmacKey[32];
//Expanded key fo control canal
WORD controlW[14*32];
//Expanded key fo data canal
WORD dataW[14*32];
//Socket to Windbg
int socket_fd;
struct sockaddr_in sa;

int pkt_number = 0;



void printKD_PACKET(KD_PACKET_HEADER* pkt){
	printf("Leader: %08x\n", pkt->Signature);
	printf("PacketType: %04x\n", pkt->PacketType);
	printf("DataSize: %d\n", pkt->DataSize);
	printf("PacketID: %08x\n", pkt->PacketID);
	printf("Checksum: %08x\n", pkt->Checksum);
	
	if(pkt->Signature == 0x00000062){
		printf("BREAKIN\n");
		return;
	}
	
	if(pkt->Signature == 0x69696969){
		if(pkt->PacketType == 0x0006){
			printf("RESET\n");
			return;
		}
	}
	
	printf("ApiNumber: %08x\n", pkt->ApiNumber);
	int i;
	for(i=0; i<pkt->DataSize; i++){
		printf("%02x ", pkt->PacketBody[i]);
		if(i%16==15){
			printf("\n");
		}
	}
	if(i%16!=15){
		printf("\n");
	}
	
	switch(pkt->ApiNumber){
		case DbgKdExceptionStateChange:
		{
			DBGKD_WAIT_STATE_CHANGE64* tmp = (DBGKD_WAIT_STATE_CHANGE64*)&pkt->PacketBody[4];
			printf("NewState %08x\n", tmp->NewState);
			printf("ProcessorLevel %04x\n", tmp->ProcessorLevel);
			printf("Processor %04x\n", tmp->Processor);
			printf("NumberProcessors %08x\n", tmp->NumberProcessors);
			printf("Thread %16lx\n", tmp->Thread);
			printf("ProgramCounter %16lx\n", tmp->ProgramCounter);
			
			//TODO: printExceptionRecord
			printf("FirstChance %08x\n", tmp->u.Exception.FirstChance);
			printf("ExceptionCode %08x\n", tmp->u.Exception.ExceptionRecord.ExceptionCode);
			printf("ExceptionFlags %08x\n", tmp->u.Exception.ExceptionRecord.ExceptionFlags);
			printf("ExceptionRecord %016lx\n", tmp->u.Exception.ExceptionRecord.ExceptionRecord);
			printf("ExceptionAddress %016lx\n", tmp->u.Exception.ExceptionRecord.ExceptionAddress);
			printf("NumberParameters %08x\n", tmp->u.Exception.ExceptionRecord.NumberParameters);
			for(i=0; i<15; i++){
				printf("ExceptionInformation[%d] %016lx\n", i, tmp->u.Exception.ExceptionRecord.ExceptionInformation[i]);
			}
			
			printf("DR6 %016lx\n", tmp->ControlReport.Dr6);
			printf("DR7 %016lx\n", tmp->ControlReport.Dr7);
			printf("EFlags %08x\n", tmp->ControlReport.EFlags);
			printf("InstructionCount %04x\n", tmp->ControlReport.InstructionCount);
			printf("ReportFlags %04x\n", tmp->ControlReport.ReportFlags);
			for(i=0; i<DBGKD_MAXSTREAM; i++){
				printf("InstructionStream[%d] %02x\n", i, tmp->ControlReport.InstructionStream[i]);
			}
			printf("SegCs %04x\n", tmp->ControlReport.SegCs);
			printf("SegDs %04x\n", tmp->ControlReport.SegDs);
			printf("SegEs %04x\n", tmp->ControlReport.SegEs);
			printf("SegFs %04x\n", tmp->ControlReport.SegFs);
			break;
		}
		case DbgKdReadVirtualMemoryApi:
		{
			DBGKD_MANIPULATE_STATE64* tmp = (DBGKD_MANIPULATE_STATE64*)&pkt->PacketBody[0];
			printf("TargetBaseAddress %016lx\n", tmp->u.ReadMemory.TargetBaseAddress);
			printf("TransferCount %08x\n", tmp->u.ReadMemory.TransferCount);
			printf("ActualBytesRead %08x\n", tmp->u.ReadMemory.ActualBytesRead);
			
			/*for(i=0; i<8; i++){
				printf("%02x ", tmp->u.ReadMemory.Data[i]);
			}
			printf("\n");*/
			break;
		}
		case DbgKdReadControlSpaceApi:
		{
			break;
		}
		case DbgKdGetRegister:
		{
			DBGKD_GET_REGISTER64* tmp = (DBGKD_GET_REGISTER64*)&pkt->PacketBody[0];
			printf("RAX %016lx\n", tmp->rax);
			printf("RBX %016lx\n", tmp->rbx);
			printf("RCX %016lx\n", tmp->rcx);
			printf("RDX %016lx\n", tmp->rdx);
			printf("RSP %016lx\n", tmp->rsp);
			printf("RBP %016lx\n", tmp->rbp);
			printf("R8 %016lx\n", tmp->r8);
			printf("R9 %016lx\n", tmp->r9);
			printf("R10 %016lx\n", tmp->r10);
			printf("R11 %016lx\n", tmp->r11);
			printf("R12 %016lx\n", tmp->r12);
			printf("R13 %016lx\n", tmp->r13);
			printf("R14 %016lx\n", tmp->r14);
			printf("R15 %016lx\n", tmp->r15);
			break;
		}
		case DbgKdGetVersionApi:
		{
			DBGKD_GET_VERSION_API64* tmp = (DBGKD_GET_VERSION_API64*)&pkt->PacketBody[4]; //TODO: [0]
			printf("KernelImageBase %016lx\n", tmp->KernelImageBase);
			printf("PsLoadedModuleList %016lx\n", tmp->PsLoadedModuleList);
			printf("DebuggerDataList %016lx\n", tmp->DebuggerDataList);
			break;
		}
		default:
		{
			printf("Unknown packet\n");
			break;
		}
	}
}

void printKDNET_PACKET(KDNET_PACKET_HEADER* pkt){
	printf("Signature: %04x\n", pkt->Signature);
	printf("ProtocolVersion: %02x\n", pkt->ProtocolVersion);
	printf("Canal: %02x\n", pkt->Canal);
}


//TODO: NO COPY !
void sendDataPkt(uint8_t *data, int dataLen){
	//TODO: magic header (8 bytes) + global pkt_number ! 
	//Replace pkt number...
	data[6] = pkt_number++;
	
	int i;
	//Add header
	KDNET_PACKET_HEADER finalPkt; //TODO: no static !
	finalPkt.Signature = 0x4742444d;//TODO: define !
	finalPkt.ProtocolVersion = 0x02;
	finalPkt.Canal = 0x0; //TODO: define !
	for(i=0; i<dataLen; i++){
		finalPkt.CipheredData[i] = data[i];
	}
	//Compute checksum whith hmachKey
	uint8_t tmpHMACSHA256[32];
	hmachSHA256((uint8_t*)&finalPkt, dataLen+6, hmacKey, tmpHMACSHA256);
#if DEBUG
	printf("\nChecksum:\n");
	for(i=0; i<16; i++){
		printf("%02x ", tmpHMACSHA256[i]);
	}
	printf("\n\n");
#endif
	//Ciphered with KEY:dataW IV:tmpHMACSHA256
	uint8_t* tmpData = cbc_encrypt(data, dataLen, dataW, tmpHMACSHA256);
	//Replace to cleartext with the ciphertext
	for(i=0; i<dataLen; i++){
		finalPkt.CipheredData[i] = tmpData[i];
	}
	//Add IV/HMAC
	for(i=0; i<16; i++){
		finalPkt.CipheredData[dataLen+i] = tmpHMACSHA256[i];
	}
	//Send on socket !
	sendto(socket_fd, &finalPkt, dataLen+6+16, 0, (struct sockaddr *)&sa,sizeof(sa));
}

/*
 * Called when a BREAKIN packet is received !
 */ 
void breakCallBack(){
	uint8_t wait_state[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x08, 0x30, 0x30, 0x30, 0x30, 0x07, 0x00, 0xf0, 0x00,
		0x26, 0x09, 0x00, 0x00, 0x8e, 0x2f, 0x00, 0x00, 0x30, 0x30, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5a, 0xf6, 0x6b, 0x02, 0xf8, 0xff, 0xff,
		0x90, 0x2b, 0xd7, 0x6b, 0x02, 0xf8, 0xff, 0xff, 0x03, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x90, 0x2b, 0xd7, 0x6b, 0x02, 0xf8, 0xff, 0xff,
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x70, 0xd9, 0x6e, 0x6d, 0x02, 0xf8, 0xff, 0xff,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x70, 0xd9, 0x6e, 0x6d, 0x02, 0xf8, 0xff, 0xff,
		0x15, 0xd4, 0xc9, 0x04, 0xa9, 0x3f, 0xc1, 0xc2, 0x83, 0xe6, 0xb3, 0x64, 0xc8, 0x4d, 0x3d, 0x09,
		0x01, 0x00, 0x00, 0x00, 0x01, 0xf8, 0xff, 0xff, 0xf0, 0x0f, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x00, 0x00, 0x10, 0x00, 0x03, 0x00,
		0xcc, 0xc3, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x10, 0x00, 0x2b, 0x00, 0x2b, 0x00, 0x53, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	sendDataPkt(wait_state, sizeof(wait_state));
}




void resetCallBack(){
	uint8_t reset_ack[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x08, 0x69, 0x69, 0x69, 0x69, 0x06, 0x00, 0x00, 0x00,
		0x26, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	sendDataPkt(reset_ack, sizeof(reset_ack));
	
	//Always send wait_state after reset...
	breakCallBack();
}

void handleKD_PACKET(KD_PACKET_HEADER* pkt){
	if(pkt->Signature == 0x00000062){
		printf("BREAKIN\n");
		breakCallBack();
		return;
	}
	
	if(pkt->Signature == 0x69696969){
		if(pkt->PacketType == 0x0006){
			printf("RESET\n");
			resetCallBack();
			return;
		}
	}
	
}

void kd_server(){
	
	//struct sockaddr_in Debuggee_sa;
	socket_fd = socket(PF_INET, SOCK_DGRAM, 0);
	if(socket_fd < 0){
		printf("socket call failed");
		exit(0);
	}
	
	memset(&sa, 0, sizeof(struct sockaddr_in));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = inet_addr("192.168.0.11");
	sa.sin_port = htons(50000);
	
	//Send POKE
	pkt_number++;
	sendto(socket_fd, poke, sizeof(poke), 0, (struct sockaddr *)&sa,sizeof(sa));
	
	//Receive POKE_RESP
	uint8_t buffer[2048];
	int n=recvfrom(socket_fd, buffer, sizeof(buffer), 0, NULL, NULL);
	//int i;
	BYTE *unciphered_poke_resp = cbc_decrypt(buffer+6, n-6-16, controlW, buffer+n-16);
	
	//Compute the data canal key with POKE_RESP
	BYTE dataKey[32];
	SHA256Context mySHA256Context;
	SHA256Init(&mySHA256Context);
	SHA256Update(&mySHA256Context, controlKey, 32);
	SHA256Update(&mySHA256Context, unciphered_poke_resp+8, 322);
	SHA256Final(&mySHA256Context, dataKey);
	aes_key_setup(dataKey, dataW, 256);
	
	
	uint8_t connection_check[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x0b, 0x00, 0xa8, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	
	sendDataPkt(connection_check, sizeof(connection_check));
	
	//Get CONN_RESP_PACKET !
	n=recvfrom(socket_fd, buffer, sizeof(buffer), 0, NULL, NULL);
	printf("Packet received : %d bytes \n", n);
	
	//Connection established !
	
	//Get next_packet !
	while(1){
		n=recvfrom(socket_fd, buffer, sizeof(buffer), 0, NULL, NULL);
		printf("Packet received : %d bytes >>>>>>\n", n);
		BYTE *unciphered_pkt = cbc_decrypt(buffer+6, n-6-16, dataW, buffer+n-16);
		printf("\n<<<<\n");

		printKD_PACKET((KD_PACKET_HEADER*)(unciphered_pkt+8));
		handleKD_PACKET((KD_PACKET_HEADER*)(unciphered_pkt+8));
	}
	
	exit(0);
}





//http://articles.sysprogs.org/kdvmware/kdcom.shtml
//http://j00ru.vexillium.org/?p=405
//http://visi.kenshoto.com/static/apidocs/vstruct.defs.kdcom-module.html
//https://code.google.com/p/reactos-mirror/source/browse/trunk/reactos/include/reactos/windbgkd.h
int main(){

	int i;
	printf("controlKey :\n");
	for(i=0; i<32; i++){
		printf("%02x ", controlKey[i]);
	}
	printf("\n");
	aes_key_setup(controlKey, controlW, 256);
	
	printf("hmacKey :\n");
	for(i=0; i<32; i++){
		hmacKey[i] = controlKey[i]^0xFF;
		printf("%02x ", hmacKey[i]);
	}
	printf("\n");
	
	kd_server();


	printf("\nPoke :\n");
	//KDNET_PACKET_HEADER* poke_pkt = (KDNET_PACKET_HEADER*)poke;
	//printKDNET_PACKET(poke_pkt);
	BYTE* tmp = cbc_decrypt(poke+6, 0x160, controlW, poke+sizeof(poke)-16);
	

	uint8_t arf[2096];
	memset(arf, 0, 2096);
	for(i=0; i<6; i++){
		arf[i] = poke[i];
	};
	for(i=0; i<0x160-16; i++){
		arf[i+6] = tmp[i];
	}
	printf("\n\n");
	for(i=0; i<0x166; i++){
		printf("%02x ", arf[i]);
		if(i%16 == 15){
			printf("\n");
		}
	}
	printf("\n");
	
	BYTE tmpSHA[32];
	hmacSHA256Context myHmacSHA256Context;
	hmacSHA256Init(&myHmacSHA256Context, hmacKey, 32);
	hmacSHA256Update(&myHmacSHA256Context, arf, 0x166);
	hmacSHA256Final(&myHmacSHA256Context, tmpSHA);
	printf("\nChecksum:\n");
	for(i=0; i<16; i++){
		printf("%02x ", tmpSHA[i]);
	}
	printf("\n\n");
	//exit(0);

	
	printf("\nPoke response :\n");
	BYTE* unciphered_poke_resp = cbc_decrypt(poke_resp+6, sizeof(poke_resp)-6-16, controlW, poke_resp+sizeof(poke_resp)-16);


	BYTE dataKey[32];
	SHA256Context mySHA256Context;
	SHA256Init(&mySHA256Context);
	SHA256Update(&mySHA256Context, controlKey, 32);
	SHA256Update(&mySHA256Context, unciphered_poke_resp+8, 322);
	SHA256Final(&mySHA256Context, dataKey);

	aes_key_setup(dataKey, dataW, 256);
	
	printf("\ndataKey :\n");
	for(i=0; i<32; i++){
		printf("%02x ", dataKey[i]);
	}
	printf("\n");
	
	printf("\nConnection Check :\n");
	cbc_decrypt(conncheck+6, sizeof(conncheck)-6-16, dataW, conncheck+sizeof(conncheck)-16);
	
	printf("\nConnection Check response:\n");
	cbc_decrypt(conncheck_resp+6, sizeof(conncheck_resp)-6-16, dataW, conncheck_resp+sizeof(conncheck_resp)-16);
	
	//...
	printf("\nPOKE (repeat):\n");
	cbc_decrypt(poke_repeat+6, 0x160, controlW, poke_repeat+sizeof(poke_repeat)-16);
	//...

	printf("\nBreak :\n");
	BYTE *unciphered_break = cbc_decrypt(break_data+6, sizeof(break_data)-6-16, dataW, break_data+sizeof(break_data)-16);
	printKD_PACKET((KD_PACKET_HEADER*)(unciphered_break+8));
	
	printf("\nWait State :\n");
	BYTE *unciphered_wait_state = cbc_decrypt(wait_state+6, sizeof(wait_state)-6-16, dataW, wait_state+sizeof(wait_state)-16);
	printKD_PACKET((KD_PACKET_HEADER*)(unciphered_wait_state+8));
	
	printf("\nReset:\n");
	BYTE *unciphered_reset = cbc_decrypt(reset+6, sizeof(reset)-6-16, dataW, reset+sizeof(reset)-16);
	printKD_PACKET((KD_PACKET_HEADER*)(unciphered_reset+8));
	
	printf("\nReset ACK:\n");
	BYTE *unciphered_reset_ack = cbc_decrypt(reset_ack+6, sizeof(reset_ack)-6-16, dataW, reset_ack+sizeof(reset_ack)-16);
	printKD_PACKET((KD_PACKET_HEADER*)(unciphered_reset_ack+8));
	
	printf("\nWait State 2:\n");
	BYTE *unciphered_wait_state2 = cbc_decrypt(wait_state2+6, sizeof(wait_state2)-6-16, dataW, wait_state2+sizeof(wait_state2)-16);
	printKD_PACKET((KD_PACKET_HEADER*)(unciphered_wait_state2+8));
	
	exit(0);

	printf("\nGet Version API REQ :\n");
	BYTE *unciphered_get_version_api_req = cbc_decrypt(get_version_api_req+6, sizeof(get_version_api_req)-6-16, dataW, get_version_api_req+sizeof(get_version_api_req)-16);
	printKD_PACKET((KD_PACKET_HEADER*)(unciphered_get_version_api_req+8));
	
	printf("\nGet Version API RESP :\n");
	BYTE *unciphered_get_version_api_resp = cbc_decrypt(get_version_api_resp+6, sizeof(get_version_api_resp)-6-16, dataW, get_version_api_resp+sizeof(get_version_api_resp)-16);
	printKD_PACKET((KD_PACKET_HEADER*)(unciphered_get_version_api_resp+8));

	printf("Read Virtual Memory API RESP\n");
	BYTE *unciphered_read_virtual_memory_api_resp = cbc_decrypt(read_virtual_memory_api_resp+6, sizeof(read_virtual_memory_api_resp)-6-16, dataW, read_virtual_memory_api_resp+sizeof(read_virtual_memory_api_resp)-16);
	printKD_PACKET((KD_PACKET_HEADER*)(unciphered_read_virtual_memory_api_resp+8));
	
	printf("Get Register RESP\n");
	BYTE* unciphered_get_register_resp = cbc_decrypt(get_register_resp+6, sizeof(get_register_resp)-6-16, dataW, get_register_resp+sizeof(get_register_resp)-16);
	printKD_PACKET((KD_PACKET_HEADER*)(unciphered_get_register_resp+8));
	
	//unciphered_break_ack = cbc_decrypt(cmd_data+6, sizeof(cmd_data)-6-16, dataW, cmd_data+sizeof(cmd_data)-16);
	//printKD_PACKET((KD_PACKET_HEADER*)(unciphered_break_ack+8));
	return 0;
}

