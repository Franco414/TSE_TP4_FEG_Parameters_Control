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
/**
 * @brief Private function that determines if the access parameter is valid.
 * if It is a valid parameter then, It stores in the private structure.
 *
 * @param c character to be processed by the FSM.
 */
static void moduleTp4_fsmSave(uint8_t c);

/**
 * @brief Private function to initialize the variables used to temporarily store the access parameter.
 *
 * @param c character to be processed by the FSM.
 */
static void moduleTp4_fsmInitData(uint8_t c);

/**
 * @brief Private function to store temporally an access parameter, It saved character by character.
 *
 * @param c character to be processed by the FSM.
 */
static void moduleTp4_fsmData(uint8_t c);

/**
 * @brief Private function to initialize the variables used to detect if the data frame contains a valid label,
 * that allows the system to identify if it is a public IP, VPN user, VPN pass.
 *
 * @param c character to be processed by the FSM.
 */
static void moduleTp4_fsmInitCompare(uint8_t c);

/**
 * @brief Private function to determine if the data frame received contains a valid label that indicate the
 * system must to storing the access parameter included in it.
 *
 * @param c character to be processed by the FSM.
 */
static void moduleTp4_fsmCompare(uint8_t c);

/**
 * @brief Private function that does nothing, its purpose is to be invoked in situations where no processing is
 * required. For example, if no event is received and if the system is sleeping.
 *
 * @param c character to be processed by the FSM.
 */
static void moduleTp4_fsmDoNothing(uint8_t c);

/**
 * @brief Private function invoked when the received packet is invalid, this resets all the variables used up
 * to this moment.
 *
 * @param c character to be processed by the FSM.
 */
static void moduleTp4_variablesReset(uint8_t c);

/**
 * @brief Private function to input a character in the FSM.
 *
 * @param c character to be processed by the FSM.
 */
static void moduleTp4_input_parameters_mef(uint8_t c);

/**
 * @brief Private function to initialize all the variables used to save the last valid package. i.e, it restarts
 * the variables used by the FSM to receive a new access parameter.
 *
 */
static void moduleTp4_fsmReset();
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
  uint8_t mef_count;
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
  uint8_t numMaxChar;
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

static const id_param_t tableIdParam[] = {{.ptr = LABEL_IP_IDENTIFIER, .len = SIZE_LABEL_IP},
                                          {.ptr = LABEL_USER_IDENTIFIER, .len = SIZE_LABEL_USER},
                                          {.ptr = LABEL_PASS_IDENTIFIER, .len = SIZE_LABEL_PASS}};

/*=================================================================================================================*/
/*                                                Public Variables                                                 */
/*=================================================================================================================*/

/*=================================================================================================================*/
/*                                          Private Data Entry: FSM Entry                                          */
/*=================================================================================================================*/
static const mef_entry_t table_mef[] = {{none_event, sleeping, sleeping, moduleTp4_fsmDoNothing},
                                        {none_event, waiting_command, waiting_command, moduleTp4_fsmCompare},
                                        {none_event, receiving_data, receiving_data, moduleTp4_fsmData},
                                        {none_event, error, sleeping, moduleTp4_variablesReset},
                                        {command, sleeping, waiting_command, moduleTp4_fsmInitCompare},
                                        {command, waiting_command, waiting_command, moduleTp4_fsmInitCompare},
                                        {command, receiving_data, waiting_command, moduleTp4_fsmInitCompare},
                                        {command, error, sleeping, moduleTp4_variablesReset},
                                        {start_param, sleeping, error, moduleTp4_variablesReset},
                                        {start_param, waiting_command, receiving_data, moduleTp4_fsmInitData},
                                        {start_param, receiving_data, error, moduleTp4_variablesReset},
                                        {start_param, error, sleeping, moduleTp4_variablesReset},
                                        {end_param, sleeping, error, moduleTp4_variablesReset},
                                        {end_param, waiting_command, error, moduleTp4_variablesReset},
                                        {end_param, receiving_data, sleeping, moduleTp4_fsmSave},
                                        {end_param, error, sleeping, moduleTp4_variablesReset}};
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

static bool IsInvalidChar(uint8_t c) {
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
  static uint8_t countField;
  static bool ret;
  static uint8_t count;
  lenIPrecv = strlen(ptr);
  maxDigByField = IP_MAX_DIGIT_BY_FIELD;
  countDig = 0;
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
  if (countField == IP_NUM_FIELD && countDig > 0 && countDig < IP_NUM_FIELD) ret = true;
  return ret;
}

static bool moduleTp4_UserToVerify(uint8_t* ptr) {
  static uint8_t lenIPrecv;
  static uint8_t count;
  static bool ret;
  static bool invalidChar;
  ret = false;
  invalidChar = false;
  lenIPrecv = strlen(ptr);
  if (lenIPrecv > userData->cfg.numMaxChar || lenIPrecv < VPN_USER_MIN_NUM_CHAR) return ret;
  for (count = 0; count < lenIPrecv; count++) {
    if (IsInvalidChar(ptr[count])) {
      invalidChar = true;
      count = lenIPrecv;
    }
  }
  if (!invalidChar) ret = true;
  lenIPrecv = 0;
  count = 0;
  return ret;
}

static bool moduleTp4_PassToVerify(uint8_t* ptr) {
  static uint8_t lenIPrecv;
  static bool ret = false;
  static bool invalidChar = false;
  static bool minusChar = false;
  static bool upperChar = false;
  static bool numberChar = false;
  static bool specialChar = false;
  lenIPrecv = strlen(ptr);
  ret = false;

  if (lenIPrecv > userData->cfg.numMaxChar || lenIPrecv < VPN_PASS_MIN_NUM_CHAR) return ret;
  for (uint8_t count = 0; count < lenIPrecv; count++) {
    if (charIsLetterMinus(ptr[count]))
      minusChar = true;
    else {
      if (charIsLetterUpper(ptr[count]))
        upperChar = true;
      else {
        if (charIsDigit(ptr[count]))
          numberChar = true;
        else {
          if (IsSpecialChar(ptr[count]))
            specialChar = true;
          else
            lenIPrecv = userData->cfg.numMaxChar;
        }
      }
    }
  }
  ret = specialChar && numberChar;
  ret = ret && minusChar;
  ret = ret && upperChar;

  invalidChar = false;
  minusChar = false;
  upperChar = false;
  numberChar = false;
  specialChar = false;
  return ret;
}

static void moduleTp4_fsmReset() {
  userData->userInput = no_receiving;
  //========================================= Section of MEF recv. variables ==========================================/
  mef.mef_count = 0;
  mef.mef_event = none_event;
  mef.mef_state = sleeping;
  memset(mef.tempTypeParam, CHARACTER_NULL, sizeof(mef.tempTypeParam));
  memset(mef.ptrAux, CHARACTER_NULL, sizeof(mef.ptrAux));
}

static void moduleTp4_fsmSave(uint8_t c) {
  switch (userData->userInput) {
    case recv_ip:
      if (moduleTp4_IpToVerify(mef.ptrAux)) {
        memset(userData->paramAccess.ipPublic, CHARACTER_NULL, sizeof(userData->paramAccess.ipPublic));
        sprintf(userData->paramAccess.ipPublic, "%s", mef.ptrAux);
      }
      break;

    case recv_user:
      if (moduleTp4_UserToVerify(mef.ptrAux)) {
        memset(userData->paramAccess.userClientVPN, CHARACTER_NULL, sizeof(userData->paramAccess.userClientVPN));
        sprintf(userData->paramAccess.userClientVPN, "%s", mef.ptrAux);
      }
      break;

    case recv_pass:
      if (moduleTp4_PassToVerify(mef.ptrAux)) {
        memset(userData->paramAccess.passClientVPN, CHARACTER_NULL, sizeof(userData->paramAccess.passClientVPN));
        sprintf(userData->paramAccess.passClientVPN, "%s", mef.ptrAux);
      }
      break;

    default:
      break;
  }
  for (uint8_t i = 0; i < sizeof(mef.ptrAux); i++) mef.ptrAux[i] = CHARACTER_NULL;
  userData->userInput = no_receiving;
  moduleTp4_fsmReset();
}

static void moduleTp4_fsmInitData(uint8_t c) {
  mef.mef_count = 0;
  memset(mef.ptrAux, CHARACTER_NULL, sizeof(mef.ptrAux));
}

static void moduleTp4_fsmData(uint8_t c) {
  static uint16_t limitChar;
  static uint16_t c_;
  c_ = c;
  if (userData->userInput == recv_ip) {
    limitChar = userData->cfg.numMaxDigIP;
  } else {
    limitChar = userData->cfg.numMaxChar;
  }

  if (mef.mef_count < limitChar) {
    strcat((char*)mef.ptrAux, (char*)&c_);
    mef.mef_count++;
  } else {
    mef.mef_state = error;
  }
}

static void moduleTp4_fsmInitCompare(uint8_t c) {
  mef.mef_count = 0;
  mef.ptrAux[0] = CHARACTER_NULL;
}

static void moduleTp4_fsmCompare(uint8_t c) {
  static uint8_t c_;
  uint8_t* dest = mef.tempTypeParam;
  c_ = c;
  if (c_ != ':') {
    while (*dest) dest++;
    *dest = c_;
  } else {
    if (!strcmp(mef.tempTypeParam, tableIdParam[0].ptr) && mef.mef_count < tableIdParam[0].len)
      userData->userInput = recv_ip;
    else {
      if (!strcmp(mef.tempTypeParam, tableIdParam[1].ptr) && mef.mef_count < tableIdParam[1].len)
        userData->userInput = recv_user;
      else {
        if (!strcmp(mef.tempTypeParam, tableIdParam[2].ptr) && mef.mef_count < tableIdParam[2].len)
          userData->userInput = recv_pass;
      }
    }
    memset(mef.tempTypeParam, CHARACTER_NULL, sizeof(mef.tempTypeParam));
    mef.mef_count = 0;
  }
}

static void moduleTp4_fsmDoNothing(uint8_t c) { ; }

static void moduleTp4_variablesReset(uint8_t c) {
  mef.mef_count = 0;
  mef.mef_event = none_event;
  mef.mef_state = sleeping;
  userData->userInput = no_receiving;
  memset(mef.tempTypeParam, CHARACTER_NULL, sizeof(mef.tempTypeParam));
  memset(mef.ptrAux, CHARACTER_NULL, sizeof(mef.ptrAux));
}

static void moduleTp4_detectSizeError() {
  static int countM=0;
  if(mef.mef_state == sleeping) countM=0;
  if (mef.mef_state == waiting_command) {
    if (countM<FSM_SIZE_PTR_TEMP_DATA_TYPE) countM++;
    else mef.mef_state = error;
  }
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
  moduleTp4_detectSizeError();
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
  userData->cfg.numMaxChar = MAX_NUM_CHARACTER;
  userData->cfg.numMaxDigIP = NUM_DIG_IP;
  userData->paramAccess.ipPublic = (uint8_t*)malloc(sizeof(uint8_t) * userData->cfg.numMaxDigIP);
  userData->paramAccess.userClientVPN = (uint8_t*)malloc(sizeof(uint8_t) * userData->cfg.numMaxChar);
  userData->paramAccess.passClientVPN = (uint8_t*)malloc(sizeof(uint8_t) * userData->cfg.numMaxChar);
  userData->modo = idle;
  //========================================= Section of MEF recv. variables ==========================================/
  mef.mef_count = 0;
  mef.start_command = MEF_INIT_COMMAND;
  mef.start_param = MEF_START_PARAM;
  mef.end_param = MEF_END_PARAM;
  mef.mef_event = none_event;
  mef.ptrAux = (uint8_t*)malloc(sizeof(uint8_t) * FSM_SIZE_PTR_AUX);
  mef.mef_state = sleeping;
  mef.tempTypeParam = (uint8_t*)malloc(sizeof(uint8_t) * FSM_SIZE_PTR_TEMP_DATA_TYPE);
  memset(mef.ptrAux, CHARACTER_NULL, sizeof(mef.ptrAux));
  memset(mef.tempTypeParam, CHARACTER_NULL, strlen(mef.tempTypeParam));
  memset(userData->paramAccess.ipPublic, CHARACTER_NULL, sizeof(userData->paramAccess.ipPublic));
  memset(userData->paramAccess.userClientVPN, CHARACTER_NULL, sizeof(userData->paramAccess.userClientVPN));
  memset(userData->paramAccess.passClientVPN, CHARACTER_NULL, sizeof(userData->paramAccess.passClientVPN));
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
