/*=================================================================================================================*/
/*                                                 Includes                                                        */
/*=================================================================================================================*/
#include "moduleTp4.h"
/*=================================================================================================================*/
/*                                             Macros Definitions                                                  */
/*=================================================================================================================*/

/*=================================================================================================================*/
/*                                        Private Methods Declarations                                             */
/*=================================================================================================================*/
static void moduleTp4_fsmSave(uint8_t c);

static void moduleTp4_fsmInitData(uint8_t c);

static void moduleTp4_fsmData(uint8_t c);

static void moduleTp4_fsmInitCompare(uint8_t c);

static void moduleTp4_fsmCompare(uint8_t c);

static void moduleTp4_fsmDoNothing(uint8_t c);

static void moduleTp4_fsmReset(uint8_t c);

static void moduleTp4_input_parameters_mef(uint8_t c);

static void moduleTp4_MefReset();
/*=================================================================================================================*/
/*                                             Private Variables                                                   */
/*=================================================================================================================*/

//========================================= Section of dataApp variables ==========================================/
typedef enum { conect2VPN, disconectFromVPN, idle } modo_t;

typedef enum { recv_ip, recv_user, recv_pass, no_receiving } recv_param_access_t;

typedef enum { none_event, command, start_param, end_param } recv_param_event_t;

typedef enum { sleeping, waiting_command, receiving_data, error } state_parameters_mef_t;

typedef void (*FsmCallback_t)(uint8_t);

typedef struct {
  recv_param_event_t event_;
  state_parameters_mef_t state_;
  state_parameters_mef_t next_state_;
  FsmCallback_t callback_;
} mef_entry_t;

typedef struct {
  recv_param_event_t mef_event;
  state_parameters_mef_t mef_state;
  uint16_t mef_count;
  bool valided_param;
  uint8_t* ptrAux;
  uint8_t* tempTypeParam;
  uint8_t start_command;
  uint8_t start_param;
  uint8_t end_param;
} mef_recv_param_t;

typedef struct {
  uint8_t* ipPublic;
  uint8_t* userClientVPN;
  uint8_t* passClientVPN;
} param_access_t;

typedef struct {
  uint8_t numMaxuint8_t;
  uint8_t numMaxDigIP;
  uint8_t connectionAttempts;
} cfg_t;

typedef struct {
  cfg_t cfg;
  param_access_t paramAccess;
  modo_t modo;
  recv_param_access_t userInput;
} tpData_s;

static tpData_s* userData;

static mef_recv_param_t mef;

typedef struct {
  uint8_t* ptr;
  uint8_t len;
} id_param_t;

static const id_param_t tableIdParam[] = {
    {.ptr = "IP", .len = 3}, {.ptr = "User", .len = 5}, {.ptr = "Pass", .len = 5}};

/*=================================================================================================================*/
/*                                                Public Variables                                                 */
/*=================================================================================================================*/

/*=================================================================================================================*/
/*                                          Private Data Entry: FSM Entry                                          */
/*=================================================================================================================*/
static const mef_entry_t table_mef[] = {{none_event, sleeping, sleeping, moduleTp4_fsmDoNothing},
                                        {none_event, waiting_command, waiting_command, moduleTp4_fsmCompare},
                                        {none_event, receiving_data, receiving_data, moduleTp4_fsmData},
                                        {none_event, error, sleeping, moduleTp4_fsmReset},
                                        {command, sleeping, waiting_command, moduleTp4_fsmInitCompare},
                                        {command, waiting_command, waiting_command, moduleTp4_fsmInitCompare},
                                        {command, receiving_data, waiting_command, moduleTp4_fsmInitCompare},
                                        {command, error, sleeping, moduleTp4_fsmReset},
                                        {start_param, sleeping, error, moduleTp4_fsmReset},
                                        {start_param, waiting_command, receiving_data, moduleTp4_fsmInitData},
                                        {start_param, receiving_data, error, moduleTp4_fsmReset},
                                        {start_param, error, sleeping, moduleTp4_fsmReset},
                                        {end_param, sleeping, error, moduleTp4_fsmReset},
                                        {end_param, waiting_command, error, moduleTp4_fsmReset},
                                        {end_param, receiving_data, sleeping, moduleTp4_fsmSave},
                                        {end_param, error, sleeping, moduleTp4_fsmReset}};
/*=================================================================================================================*/
/*                                                Private Methods                                                  */
/*=================================================================================================================*/
static bool charIsDigit(uint8_t c) { return c >= '0' && c <= '9'; }

static bool charIsLetterUpper(uint8_t c) { return c >= 'A' && c <= 'Z'; }

static bool charIsLetterMinus(uint8_t c) { return c >= 'a' && c <= 'z'; }

static bool IsSpecialChar(uint8_t c) {
  static bool ret;
  ret = false;
  if ((c >= '!' && c <= '+') || (c >= '<' && c <= '@')) ret = true;
  return ret;
}

static bool IsInvaliduint8_t(uint8_t c) {
  static bool ret;
  static bool aux;
  aux = false;
  ret = false;
  aux = charIsDigit(c);
  aux = aux || charIsLetterMinus(c);
  aux = aux || charIsLetterUpper(c);
  aux = aux || IsSpecialChar(c);
  if (!aux)
    ret = true;
  else
    ret = false;
  return ret;
}

static bool moduleTp4_IpToVerify(uint8_t* ptr) {
  static uint8_t lenIPrecv;
  static uint8_t maxDigByField;
  static uint8_t countDig;
  static uint8_t numField;
  static uint8_t countField;
  static bool ret;
  static uint8_t count;
  lenIPrecv = strlen(ptr);
  maxDigByField = 3;
  countDig = 0;
  numField = 4;
  countField = 1;
  ret = false;

  if (lenIPrecv > userData->cfg.numMaxDigIP || lenIPrecv == 0) return ret;
  for (count = 0; count < lenIPrecv; count++) {
    if (charIsDigit(ptr[count])) {
      if (++countDig > maxDigByField) {
        ret = false;
        count = lenIPrecv;
      }
    } else {
      if (ptr[count] == '.' && countDig > 0) {
        countDig = 0;
        countField++;
      } else {
        countField = 0;
        ret = false;
        count = lenIPrecv;
      }
    }
  }
  if (countField == 4 && countDig > 0 && countDig < 4) ret = true;
  return ret;
}

static bool moduleTp4_UserToVerify(uint8_t* ptr) {
  static uint8_t lenIPrecv;
  static uint8_t count;
  static bool ret;
  static bool invaliduint8_t;
  ret = false;
  invaliduint8_t = false;
  lenIPrecv = strlen(ptr);
  if (lenIPrecv > userData->cfg.numMaxuint8_t || lenIPrecv < 6) return ret;
  for (count = 0; count < lenIPrecv; count++) {
    if (IsInvaliduint8_t(ptr[count])) {
      invaliduint8_t = true;
      count = lenIPrecv;
    }
  }
  if (!invaliduint8_t) ret = true;
  lenIPrecv = 0;
  count = 0;
  return ret;
}

static bool moduleTp4_PassToVerify(uint8_t* ptr) {
  static uint8_t lenIPrecv;
  static bool ret = false;
  static bool invaliduint8_t = false;
  static bool minusuint8_t = false;
  static bool upperuint8_t = false;
  static bool numberuint8_t = false;
  static bool specialuint8_t = false;
  lenIPrecv = strlen(ptr);
  ret = false;

  if (lenIPrecv > userData->cfg.numMaxuint8_t || lenIPrecv < 8) return ret;
  for (uint8_t count = 0; count < lenIPrecv; count++) {
    if (charIsLetterMinus(ptr[count]))
      minusuint8_t = true;
    else {
      if (charIsLetterUpper(ptr[count]))
        upperuint8_t = true;
      else {
        if (charIsDigit(ptr[count]))
          numberuint8_t = true;
        else {
          if (IsSpecialChar(ptr[count]))
            specialuint8_t = true;
          else
            lenIPrecv = userData->cfg.numMaxuint8_t;
        }
      }
    }
  }
  ret = specialuint8_t && numberuint8_t;
  ret = ret && minusuint8_t;
  ret = ret && upperuint8_t;

  invaliduint8_t = false;
  minusuint8_t = false;
  upperuint8_t = false;
  numberuint8_t = false;
  specialuint8_t = false;
  return ret;
}

static void moduleTp4_MefReset() {
  userData->userInput = no_receiving;
  //========================================= Section of MEF recv. variables ==========================================/
  mef.mef_count = 0;
  mef.mef_event = none_event;
  mef.mef_state = sleeping;
  mef.valided_param = false;
  memset(mef.tempTypeParam, '\0', sizeof(mef.tempTypeParam));
  memset(mef.ptrAux, '\0', sizeof(mef.ptrAux));
}

static void moduleTp4_fsmSave(uint8_t c) {
  switch (userData->userInput) {
    case recv_ip:
      if (moduleTp4_IpToVerify(mef.ptrAux)) {
        memset(userData->paramAccess.ipPublic, '\0', sizeof(userData->paramAccess.ipPublic));
        sprintf(userData->paramAccess.ipPublic, "%s", mef.ptrAux);
      }
      break;

    case recv_user:
      if (moduleTp4_UserToVerify(mef.ptrAux)) {
        memset(userData->paramAccess.userClientVPN, '\0', sizeof(userData->paramAccess.userClientVPN));
        sprintf(userData->paramAccess.userClientVPN, "%s", mef.ptrAux);
      }
      break;

    case recv_pass:
      if (moduleTp4_PassToVerify(mef.ptrAux)) {
        memset(userData->paramAccess.passClientVPN, '\0', sizeof(userData->paramAccess.passClientVPN));
        sprintf(userData->paramAccess.passClientVPN, "%s", mef.ptrAux);
      }
      break;

    default:
      break;
  }
  for (uint8_t i = 0; i < sizeof(mef.ptrAux); i++) mef.ptrAux[i] = '\0';
  userData->userInput = no_receiving;
  moduleTp4_MefReset();
}

static void moduleTp4_fsmInitData(uint8_t c) {
  mef.mef_count = 0;
  memset(mef.ptrAux, 0, sizeof(mef.ptrAux));
}

static void moduleTp4_fsmData(uint8_t c) {
  static uint16_t limitChar;
  static uint16_t c_;
  c_ = c;
  ;
  if (userData->userInput == recv_ip) {
    limitChar = userData->cfg.numMaxDigIP;
  } else {
    limitChar = userData->cfg.numMaxuint8_t;
  }

  if (mef.mef_count < limitChar) {
    strcat((char*)mef.ptrAux, (char*)&c_);
    mef.mef_count++;
  } else
    userData->userInput = no_receiving;
}

static void moduleTp4_fsmInitCompare(uint8_t c) { mef.mef_count = 0; }

static void moduleTp4_fsmCompare(uint8_t c) {
  static uint8_t countTemp;
  static uint8_t c_;
  c_ = c;
  if (c_ != ':') {
    strcat((char*)mef.tempTypeParam, (char*)&c_);
  } else {
    if (!strcmp(mef.tempTypeParam, tableIdParam[0].ptr) && countTemp < tableIdParam[0].len)
      userData->userInput = recv_ip;
    else {
      if (!strcmp(mef.tempTypeParam, tableIdParam[1].ptr) && countTemp < tableIdParam[1].len)
        userData->userInput = recv_user;
      else {
        if (!strcmp(mef.tempTypeParam, tableIdParam[2].ptr) && countTemp < tableIdParam[2].len)
          userData->userInput = recv_pass;
        else
          userData->userInput = no_receiving;
      }
    }
    countTemp++;
    countTemp = 0;
    memset(mef.tempTypeParam, 0, sizeof(mef.tempTypeParam));
  }
}

static void moduleTp4_fsmDoNothing(uint8_t c) { ; }

static void moduleTp4_fsmReset(uint8_t c) {
  mef.mef_count = 0;
  mef.mef_event = none_event;
  mef.valided_param = false;
}

static void moduleTp4_input_parameters_mef(uint8_t c) {
  static uint16_t lenTableMef = sizeof(table_mef) / sizeof(table_mef[0]);
  static uint16_t i = 0;

  mef.mef_event = none_event;

  if (c == mef.start_command && mef.mef_state == sleeping) mef.mef_event = command;

  if (c == mef.start_param && mef.mef_state == waiting_command) mef.mef_event = start_param;

  if (c == mef.end_param && mef.mef_state == receiving_data) mef.mef_event = end_param;

  for (i = 0; i < lenTableMef; i++) {
    if (table_mef[i].state_ == mef.mef_state && table_mef[i].event_ == mef.mef_event) {
      mef.mef_state = table_mef[i].next_state_;
      table_mef[i].callback_(c);
      break;
    }
  }
}

static tpData_t moduleTp4_instance_object() {
  static tpData_s* arrayObj[MAX_INSTANCE_OBJ];
  tpData_s* ret;
  static uint16_t count = 0;
  if (count < MAX_INSTANCE_OBJ) {
    arrayObj[count] = (tpData_s*)malloc(sizeof(tpData_s));
    ret = arrayObj[count++];
  } else {
    ret = NULL;
  }
  return (tpData_t)ret;
}

/*=================================================================================================================*/
/*                                                Public Methods                                                   */
/*=================================================================================================================*/

void moduleTp4_appInit() {
  userData = (tpData_s*)moduleTp4_instance_object();
  userData->cfg.connectionAttempts = NUM_CONNECTION_ATTEMPTS;
  userData->cfg.numMaxuint8_t = MAX_NUM_CHARACTER;
  userData->cfg.numMaxDigIP = NUM_DIG_IP;
  userData->paramAccess.ipPublic = (uint8_t*)malloc(sizeof(uint8_t) * userData->cfg.numMaxDigIP);
  userData->paramAccess.userClientVPN = (uint8_t*)malloc(sizeof(uint8_t) * userData->cfg.numMaxuint8_t);
  userData->paramAccess.passClientVPN = (uint8_t*)malloc(sizeof(uint8_t) * userData->cfg.numMaxuint8_t);
  userData->modo = idle;
  //========================================= Section of MEF recv. variables ==========================================/
  mef.mef_count = 0;
  mef.start_command = MEF_INIT_COMMAND;
  mef.start_param = MEF_START_PARAM;
  mef.end_param = MEF_END_PARAM;
  mef.mef_event = none_event;
  mef.ptrAux = (uint8_t*)malloc(sizeof(uint8_t) * 20);
  mef.mef_state = sleeping;
  mef.tempTypeParam = (uint8_t*)malloc(sizeof(uint8_t) * 10);
  memset(mef.ptrAux, '\0', sizeof(mef.ptrAux));
  memset(mef.tempTypeParam, '\0', strlen(mef.tempTypeParam));
  memset(userData->paramAccess.ipPublic, '\0', sizeof(userData->paramAccess.ipPublic));
  memset(userData->paramAccess.userClientVPN, '\0', sizeof(userData->paramAccess.userClientVPN));
  memset(userData->paramAccess.passClientVPN, '\0', sizeof(userData->paramAccess.passClientVPN));
}

void moduleTp4_appFinish() {
  free((void*)userData->paramAccess.ipPublic);
  free((void*)userData->paramAccess.userClientVPN);
  free((void*)userData->paramAccess.passClientVPN);
  free((void*)userData);
  free((void*)mef.ptrAux);
  free((void*)mef.tempTypeParam);
}

tpData_t moduleTp4_getObj() {
  tpData_s* ret = userData;
  return (tpData_t)ret;
}

void moduleTp4_typingParam(uint8_t c) {
  static uint8_t c_;
  c_ = c;
  moduleTp4_input_parameters_mef(c_);
}

uint8_t* moduleTp4_getIPpublic(tpData_t ptr) {
  tpData_s* aux = (tpData_s*)ptr;
  return aux->paramAccess.ipPublic;
}

uint8_t* moduleTp4_getUser(tpData_t ptr) {
  tpData_s* aux = (tpData_s*)ptr;
  return aux->paramAccess.userClientVPN;
}

uint8_t* moduleTp4_getPass(tpData_t ptr) {
  tpData_s* aux = (tpData_s*)ptr;
  return aux->paramAccess.passClientVPN;
}
