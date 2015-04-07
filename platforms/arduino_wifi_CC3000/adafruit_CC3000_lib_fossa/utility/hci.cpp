/*****************************************************************************
*
*  hci.c  - CC3000 Host Driver Implementation.
*  Copyright (C) 2011 Texas Instruments Incorporated - http://www.ti.com/
*
* Adapted for use with the Arduino/AVR by KTOWN (Kevin Townsend)
* & Limor Fried for Adafruit Industries
* This library works with the Adafruit CC3000 breakout
*	----> https://www.adafruit.com/products/1469
* Adafruit invests time and resources providing this open source code,
* please support Adafruit and open-source hardware by purchasing
* products from Adafruit!
*
*  Redistribution and use in source and binary forms, with or without
*  modification, are permitted provided that the following conditions
*  are met:
*
*    Redistributions of source code must retain the above copyright
*    notice, this list of conditions and the following disclaimer.
*
*    Redistributions in binary form must reproduce the above copyright
*    notice, this list of conditions and the following disclaimer in the
*    documentation and/or other materials provided with the
*    distribution.
*
*    Neither the name of Texas Instruments Incorporated nor the names of
*    its contributors may be used to endorse or promote products derived
*    from this software without specific prior written permission.
*
*  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
*  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
*  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
*  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
*  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
*  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
*  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
*  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
*  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
*  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
*  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*
*****************************************************************************/

//*****************************************************************************
//
//! \addtogroup hci_app
//! @{
//
//*****************************************************************************

#include "cc3000_common.h"
#include "hci.h"
// Adafruit CC3k Host Driver Difference
// Reference our SPI driver in the parent folder.
// Noted 12-12-2014 by tdicola
#include "../ccspi.h"
#include "evnt_handler.h"
#include "wlan.h"

#define SL_PATCH_PORTION_SIZE (1000)

//*****************************************************************************
//
//!  hci_command_send
//!
//!  @param  usOpcode     command operation code
//!  @param  pucBuff      pointer to the command's arguments buffer
//!  @param  ucArgsLength length of the arguments
//!
//!  @return              none
//!
//!  @brief               Initiate an HCI command.
//
//*****************************************************************************
UINT16 hci_command_send(UINT16 usOpcode, UINT8 *pucBuff, UINT8 ucArgsLength) {
  UINT8 *stream;

  stream = (pucBuff + SPI_HEADER_SIZE);

  UINT8_TO_STREAM(stream, HCI_TYPE_CMND);
  stream = UINT16_TO_STREAM(stream, usOpcode);
  UINT8_TO_STREAM(stream, ucArgsLength);

  // Update the opcode of the event we will be waiting for
  SpiWrite(pucBuff, ucArgsLength + SIMPLE_LINK_HCI_CMND_HEADER_SIZE);

  return (0);
}

//*****************************************************************************
//
//!  hci_data_send
//!
//!  @param  usOpcode        command operation code
//!	 @param  ucArgs					 pointer to the command's
//arguments buffer
//!  @param  usArgsLength    length of the arguments
//!  @param  ucTail          pointer to the data buffer
//!  @param  usTailLength    buffer length
//!
//!  @return none
//!
//!  @brief              Initiate an HCI data write operation
//
//*****************************************************************************
INT32 hci_data_send(UINT8 ucOpcode, UINT8 *ucArgs, UINT16 usArgsLength,
                    UINT16 usDataLength, const UINT8 *ucTail,
                    UINT16 usTailLength) {
  UINT8 *stream;

  stream = ((ucArgs) + SPI_HEADER_SIZE);

  UINT8_TO_STREAM(stream, HCI_TYPE_DATA);
  UINT8_TO_STREAM(stream, ucOpcode);
  UINT8_TO_STREAM(stream, usArgsLength);
  stream = UINT16_TO_STREAM(stream, usArgsLength + usDataLength + usTailLength);

  // Send the packet over the SPI
  SpiWrite(ucArgs, SIMPLE_LINK_HCI_DATA_HEADER_SIZE + usArgsLength +
                       usDataLength + usTailLength);

  return (ESUCCESS);
}

//*****************************************************************************
//
//!  hci_data_command_send
//!
//!  @param  usOpcode      command operation code
//!  @param  pucBuff       pointer to the data buffer
//!  @param  ucArgsLength  arguments length
//!  @param  ucDataLength  data length
//!
//!  @return none
//!
//!  @brief              Prepeare HCI header and initiate an HCI data write
//operation
//
//*****************************************************************************
void hci_data_command_send(UINT16 usOpcode, UINT8 *pucBuff, UINT8 ucArgsLength,
                           UINT16 ucDataLength) {
  UINT8 *stream = (pucBuff + SPI_HEADER_SIZE);

  UINT8_TO_STREAM(stream, HCI_TYPE_DATA);
  UINT8_TO_STREAM(stream, usOpcode);
  UINT8_TO_STREAM(stream, ucArgsLength);
  stream = UINT16_TO_STREAM(stream, ucArgsLength + ucDataLength);

  // Send the command over SPI on data channel
  SpiWrite(pucBuff,
           ucArgsLength + ucDataLength + SIMPLE_LINK_HCI_DATA_CMND_HEADER_SIZE);

  return;
}

//*****************************************************************************
//
//!  hci_patch_send
//!
//!  @param  usOpcode      command operation code
//!  @param  pucBuff       pointer to the command's arguments buffer
//!  @param  patch         pointer to patch content buffer
//!  @param  usDataLength  data length
//!
//!  @return              none
//!
//!  @brief               Prepeare HCI header and initiate an HCI patch write
//operation
//
//*****************************************************************************
void hci_patch_send(UINT8 ucOpcode, UINT8 *pucBuff, CHAR *patch,
                    UINT16 usDataLength) {
  UINT8 *data_ptr = (pucBuff + SPI_HEADER_SIZE);
  UINT16 usTransLength;
  UINT8 *stream = (pucBuff + SPI_HEADER_SIZE);

  UINT8_TO_STREAM(stream, HCI_TYPE_PATCH);
  UINT8_TO_STREAM(stream, ucOpcode);
  stream = UINT16_TO_STREAM(stream,
                            usDataLength + SIMPLE_LINK_HCI_PATCH_HEADER_SIZE);

  if (usDataLength <= SL_PATCH_PORTION_SIZE) {
    UINT16_TO_STREAM(stream, usDataLength);
    stream = UINT16_TO_STREAM(stream, usDataLength);
    memcpy((pucBuff + SPI_HEADER_SIZE) + HCI_PATCH_HEADER_SIZE, patch,
           usDataLength);

    // Update the opcode of the event we will be waiting for
    SpiWrite(pucBuff, usDataLength + HCI_PATCH_HEADER_SIZE);
  } else {
    usTransLength = (usDataLength / SL_PATCH_PORTION_SIZE);
    UINT16_TO_STREAM(stream,
                     usDataLength + SIMPLE_LINK_HCI_PATCH_HEADER_SIZE +
                         usTransLength * SIMPLE_LINK_HCI_PATCH_HEADER_SIZE);
    stream = UINT16_TO_STREAM(stream, SL_PATCH_PORTION_SIZE);
    memcpy(pucBuff + SPI_HEADER_SIZE + HCI_PATCH_HEADER_SIZE, patch,
           SL_PATCH_PORTION_SIZE);
    usDataLength -= SL_PATCH_PORTION_SIZE;
    patch += SL_PATCH_PORTION_SIZE;

    // Update the opcode of the event we will be waiting for
    SpiWrite(pucBuff, SL_PATCH_PORTION_SIZE + HCI_PATCH_HEADER_SIZE);

    while (usDataLength) {
      // Adafruit CC3k Host Driver Difference
      // Check for missed interrupt to try to make code more reliable.
      // Noted 12-12-2014 by tdicola
      cc3k_int_poll();

      if (usDataLength <= SL_PATCH_PORTION_SIZE) {
        usTransLength = usDataLength;
        usDataLength = 0;

      } else {
        usTransLength = SL_PATCH_PORTION_SIZE;
        usDataLength -= usTransLength;
      }

      *(UINT16 *) data_ptr = usTransLength;
      memcpy(data_ptr + SIMPLE_LINK_HCI_PATCH_HEADER_SIZE, patch,
             usTransLength);
      patch += usTransLength;

      // Update the opcode of the event we will be waiting for
      SpiWrite((UINT8 *) data_ptr, usTransLength + sizeof(usTransLength));
    }
  }
}

//*****************************************************************************
//
// Close the Doxygen group.
//! @}
//
//
//*****************************************************************************
