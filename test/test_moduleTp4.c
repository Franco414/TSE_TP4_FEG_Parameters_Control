/*=================================================================================================================*/
/*                                                 Includes                                                        */
/*=================================================================================================================*/
#include <stdbool.h>

#include "moduleTp4.h"
#include "unity.h"

/*=================================================================================================================*/
/*                                             Private Variables                                                   */
/*=================================================================================================================*/
typedef struct {
  char* send;
  char* param;
  uint8_t len;
} Examples_t;

static const Examples_t valid_cases_ip[] = {
    {.send = ">IP:\"192.168.1.1\"", .param = "192.168.1.1", .len = 11},
    {.send = ">IP:\"10.10.10.10\"", .param = "10.10.10.10", .len = 11},
    {.send = ">IP:\"1.0.0.1\"", .param = "1.0.0.1", .len = 7},
    {.send = ">IP:\"123.456.789.110\"", .param = "123.456.789.110", .len = 15},
};

static const Examples_t valid_cases_user[] = {
    {.send = ">User:\"franco\"", .param = "franco", .len = 6},
    {.send = ">User:\"AAAUPPER\"", .param = "AAAUPPER", .len = 8},
    {.send = ">User:\"userminus\"", .param = "userminus", .len = 9},
    {.send = ">User:\"Rhsy972h\"", .param = "Rhsy972h", .len = 8},
};

static const Examples_t valid_cases_pass[] = {
    {.send = ">Pass:\"Rey414@d\"", .param = "Rey414@d", .len = 8},
    {.send = ">Pass:\"10frWe2r+\"", .param = "10frWe2r+", .len = 9},
    {.send = ">Pass:\"vWeF!a235A5\"", .param = "vWeF!a235A5", .len = 11},
    {.send = ">Pass:\"user@0321FEG\"", .param = "user@0321FEG", .len = 12},
};

static Examples_t Invalid_cases_ip[] = {
    // First a valid parameter is loaded, and then it sends erroneous commands to verify that the first parameter has
    // not been modified.
    {.send = ">IP:\"10.10.10.10\"", .param = "10.10.10.10", .len = 11},
    {.send = ">IP:\"abc.def.ghi.jkl\"", .param = "10.10.10.10", .len = 11},
    {.send = ">IP:\"123..111.10\"", .param = "10.10.10.10", .len = 11},
    {.send = ">IP:\"192.168.1a.1\"", .param = "10.10.10.10", .len = 11},
    {.send = ">IP:\"123.141.15.1234\"", .param = "10.10.10.10", .len = 11},
};

static Examples_t Invalid_cases_user[] = {
    // First a valid parameter is loaded, and then it sends erroneous commands to verify that the first parameter has
    // not been modified.
    {.send = ">User:\"userExample\"", .param = "userExample", .len = 11},
    {.send = ">User:\"thanGreaterMAX\"", .param = "userExample", .len = 11},
    {.send = ">User:\"few\"", .param = "userExample", .len = 11},
    {.send = ">User:\"abcde\"", .param = "userExample", .len = 11},
    {.send = ">User:\"\"", .param = "userExample", .len = 11},
};

static Examples_t Invalid_cases_pass[] = {
    // First a valid parameter is loaded, and then it sends erroneous commands to verify that the first parameter has
    // not been modified.
    {.send = ">Pass:\"Rey414@d\"", .param = "Rey414@d", .len = 8},
    {.send = ">Pass:\"10frWe2r\"", .param = "Rey414@d", .len = 8},
    {.send = ">Pass:\"sinCharEsp01\"", .param = "Rey414@d", .len = 8},
    {.send = ">Passs:\"Ras414@@12\"", .param = "Rey414@d", .len = 8},
};
/*=================================================================================================================*/
/*                                             Public Variables                                                    */
/*=================================================================================================================*/
static tpData_t testUserData;
/*=================================================================================================================*/
/*                                       Public Funtions - setUP - tearDown                                        */
/*=================================================================================================================*/
void setUp(void) {
  moduleTp4_appInit();
  testUserData = moduleTp4_getObj();
}
void tearDown(void) { moduleTp4_appFinish(); }
/*=================================================================================================================*/
/*                                            Public Test Funtions                                                 */
/*=================================================================================================================*/

void test_moduleTp4_validIP(void) {
  char msg[200];
  for (uint16_t count = 0; count < (sizeof(valid_cases_ip) / sizeof(Examples_t)); count++) {
    for (uint8_t index = 0; index < strlen(valid_cases_ip[count].send); index++)
      moduleTp4_typingParam(valid_cases_ip[count].send[index]);
    sprintf(msg, "Example Valid Pass: %d, Expected: %s, Received: %s", count + 1, valid_cases_ip[count].param,
            moduleTp4_getIPpublic(testUserData));
    TEST_ASSERT_EQUAL_INT8_ARRAY_MESSAGE(valid_cases_ip[count].param, moduleTp4_getIPpublic(testUserData),
                                         valid_cases_ip[count].len, msg);
  }
}

void test_validUser(void) {
  char msg[200];
  for (uint16_t count = 0; count < (sizeof(valid_cases_user) / sizeof(Examples_t)); count++) {
    for (uint8_t index = 0; index < strlen(valid_cases_user[count].send); index++)
      moduleTp4_typingParam(valid_cases_user[count].send[index]);
    sprintf(msg, "Example Valid Pass: %d, Expected: %s, Received: %s", count + 1, valid_cases_user[count].param,
            moduleTp4_getUser(testUserData));
    TEST_ASSERT_EQUAL_INT8_ARRAY_MESSAGE(valid_cases_user[count].param, moduleTp4_getUser(testUserData),
                                         valid_cases_user[count].len, msg);
  }
}

void test_validPass(void) {
  char msg[200];
  for (uint16_t count = 0; count < (sizeof(valid_cases_pass) / sizeof(Examples_t)); count++) {
    for (uint8_t index = 0; index < strlen(valid_cases_pass[count].send); index++)
      moduleTp4_typingParam(valid_cases_pass[count].send[index]);
    sprintf(msg, "Example Valid Pass: %d, Expected: %s, Received: %s", count + 1, valid_cases_pass[count].param,
            moduleTp4_getPass(testUserData));
    TEST_ASSERT_EQUAL_INT8_ARRAY_MESSAGE(valid_cases_pass[count].param, moduleTp4_getPass(testUserData),
                                         valid_cases_pass[count].len, msg);
  }
}

void test_InvalidIP(void) {
  char msg[200];
  for (uint16_t count = 0; count < (sizeof(Invalid_cases_ip) / sizeof(Examples_t)); count++) {
    for (uint8_t index = 0; index < strlen(Invalid_cases_ip[count].send); index++)
      moduleTp4_typingParam(Invalid_cases_ip[count].send[index]);
    sprintf(msg, "Example Valid Pass: %d, Expected: %s, Received: %s", count + 1, valid_cases_ip[count].param,
            moduleTp4_getIPpublic(testUserData));
    TEST_ASSERT_EQUAL_INT8_ARRAY_MESSAGE(Invalid_cases_ip[count].param, moduleTp4_getIPpublic(testUserData),
                                         Invalid_cases_ip[count].len, msg);
  }
}

void test_InvalidUser(void) {
  char msg[200];
  for (uint16_t count = 0; count < (sizeof(Invalid_cases_user) / sizeof(Examples_t)); count++) {
    for (uint8_t index = 0; index < strlen(Invalid_cases_user[count].send); index++)
      moduleTp4_typingParam(Invalid_cases_user[count].send[index]);
    sprintf(msg, "Example Valid Pass: %d, Expected: %s, Received: %s", count + 1, valid_cases_user[count].param,
            moduleTp4_getUser(testUserData));
    TEST_ASSERT_EQUAL_INT8_ARRAY_MESSAGE(Invalid_cases_user[count].param, moduleTp4_getUser(testUserData),
                                         Invalid_cases_user[count].len, msg);
  }
}
void test_InvalidPass(void) {
  char msg[200];
  for (uint16_t count = 0; count < (sizeof(Invalid_cases_pass) / sizeof(Examples_t)); count++) {
    for (uint8_t index = 0; index < strlen(Invalid_cases_pass[count].send); index++)
      moduleTp4_typingParam(Invalid_cases_pass[count].send[index]);
    sprintf(msg, "Example Valid Pass: %d, Expected: %s, Received: %s", count + 1, valid_cases_pass[count].param,
            moduleTp4_getPass(testUserData));
    TEST_ASSERT_EQUAL_INT8_ARRAY_MESSAGE(Invalid_cases_pass[count].param, moduleTp4_getPass(testUserData),
                                         Invalid_cases_pass[count].len, msg);
  }
}