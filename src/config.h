#ifndef __CONFIG_H__
#define __CONFIG_H__
/*=================================================================================================================*/
/*                                                 Includes                                                        */
/*=================================================================================================================*/

/*=================================================================================================================*/
/*                                             Macros Definitions                                                  */
/*=================================================================================================================*/
#define MAX_INSTANCE_OBJ 8

/*============================================= User config =======================================================*/
#define NUM_CONNECTION_ATTEMPTS 10
#define MAX_NUM_CHARACTER 12
#define NUM_DIG_IP 16
#define CHARACTER_NULL '\0'
/*========================================= User's Labels config ==================================================*/
#define LABEL_IP_IDENTIFIER "IP"
#define LABEL_USER_IDENTIFIER "User"
#define LABEL_PASS_IDENTIFIER "Pass"

#define SIZE_LABEL_IP strlen(LABEL_IP_IDENTIFIER)
#define SIZE_LABEL_USER strlen(LABEL_USER_IDENTIFIER)
#define SIZE_LABEL_PASS strlen(LABEL_PASS_IDENTIFIER)
/*============================================ fsm parameters =====================================================*/
#define MEF_START_PARAM '\"'
#define MEF_END_PARAM '\"'
#define MEF_INIT_COMMAND '>'
#define FSM_SIZE_PTR_AUX 20
#define FSM_SIZE_PTR_TEMP_DATA_TYPE 10
/*=========================================== IP's Validation =====================================================*/
#define IP_NUM_FIELD 4
#define IP_MAX_DIGIT_BY_FIELD 3
/*========================================= VPN User Validation ===================================================*/
#define VPN_USER_MIN_NUM_CHAR 6
/*========================================= VPN Pass Validation ===================================================*/
#define VPN_PASS_MIN_NUM_CHAR 8
/*=================================================================================================================*/
/*                                             Types Variables                                                     */
/*=================================================================================================================*/

/*=================================================================================================================*/
/*                                        Public Function declarations                                             */
/*=================================================================================================================*/
#endif