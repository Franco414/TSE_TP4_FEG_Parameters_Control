#ifndef __MODULETP4_H__
#define __MODULETP4_H__
/*=================================================================================================================*/
/*                                                 Includes                                                        */
/*=================================================================================================================*/
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
/*=================================================================================================================*/
/*                                             Macros Definitions                                                  */
/*=================================================================================================================*/

/*=================================================================================================================*/
/*                                             Types Variables                                                     */
/*=================================================================================================================*/
typedef struct tpData_s* tpData_t;
/*=================================================================================================================*/
/*                                        Public Function declarations                                             */
/*=================================================================================================================*/
/**
 * @brief Function to finish the execution of the application moduleTp4.
 *
 */
void moduleTp4_appFinish();

/**
 * @brief This function init the execution of the application moduleTp4.
 *
 */
void moduleTp4_appInit();

/**
 * @brief Gets the address of the memory block that contains the private structure with the current access parameters.
 *
 * @return tpData_t returns the memory address that points to the private structure.
 */
tpData_t moduleTp4_getObj();

/**
 * @brief Function to enter a character of an access parameter.
 *
 * @param c Character to enter into the App.
 */
void moduleTp4_typingParam(uint8_t c);

/**
 * @brief Function to get the memory address that contains the public IP currently configured in the system.
 *
 * @param ptr Pointer that points to the private structure that contains the public IP to getting.
 * @return uint8_t* returns the memory address that contains the character array that storage the public IP.
 */
uint8_t* moduleTp4_getIPpublic(tpData_t ptr);

/**
 * @brief Function to get the memory address that contains the VPN user currently configured in the system.
 *
 * @param ptr Pointer that points to the private structure that contains the VPN user to getting.
 * @return uint8_t* Returns the memory address that contains the character array that storage the VPN user.
 */
uint8_t* moduleTp4_getUser(tpData_t ptr);

/**
 * @brief Function to get the memory address that contains the VPN pass currently configured in the system.
 *
 * @param ptr Pointer that points to the private structure that contains the VPN pass to getting.
 * @return uint8_t* Returns the memory address that contains the character array that storage the VPN pass.
 */
uint8_t* moduleTp4_getPass(tpData_t ptr);

#endif
