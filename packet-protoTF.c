/* packet-protoTF.c
 * Routines for TinkerForge protocol packet disassembly
 * By Ishraq Ibne Ashraf <ishraq86@gmail.com>
 * Copyright 2013 Ishraq Ibne Ashraf
 *
 * $Id: packet-protoTF.c 48634 2013-03-29 00:26:23Z eapache $
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <inttypes.h>
#include <glib.h>
#include <epan/packet.h>
#include <epan/dissectors/packet-usb.h>
#include <epan/prefs.h>

// defines
#define protoTF_PORT 4223
#define protoTF_USB_VENDOR_ID 0x16D0
#define protoTF_USB_PRODUCT_ID 0x063D
#define BASE58_MAX_STR_SIZE 13

// protocol naming strings
static const char *protoTF_proto_name = "TinkerForge Protocol";
static const char *protoTF_proto_name_tcp = "protoTF_TCP";
static const char *protoTF_proto_name_usb = "protoTF_USB";
static const char *protoTF_proto_name_udp = "protoTF_UDP";

// variables for creating the tree
static int proto_protoTF = -1;
static gint ett_protoTF = -1;
static proto_tree *protoTF_tree = NULL;

// header field variables
static int hf_protoTF_uid_string = -1;
static int hf_protoTF_uid_numeric = -1;
static int hf_protoTF_length = -1;
static int hf_protoTF_function_id = -1;
static int hf_protoTF_sequence_number = -1;
static int hf_protoTF_R = -1;
static int hf_protoTF_A = -1;
static int hf_protoTF_OO = -1;
static int hf_protoTF_E = -1;
static int hf_protoTF_future_use = -1;
static int hf_protoTF_data = -1;

// bit and byte offsets for dissection
static gint byte_offset = 0;
static gint byte_count_protoTF_uid = 4;
static gint byte_count_protoTF_length = 1;
static gint byte_count_protoTF_function_id = 1;
static gint byte_count_protoTF_flags= 2;
static gint byte_count_protoTF_data = -1;
static gint bit_offset = 48;
static gint bit_count_protoTF_sequence_number = 4;
static gint bit_count_protoTF_R = 1;
static gint bit_count_protoTF_A = 1;
static gint bit_count_protoTF_OO = 2;
static gint bit_count_protoTF_E = 2;
static gint bit_count_protoTF_future_use = 6;

// base58 encoding variables
static char protoTF_uid_string[BASE58_MAX_STR_SIZE];
static const char BASE58_ALPHABET[] = 
	"123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ";

// function for encoding a number to base58 string
static void base58_encode(uint32_t value, char* str) {

        uint32_t mod;
        char reverse_str[BASE58_MAX_STR_SIZE] = {'\0'};
        int i = 0;
        int k = 0;

        while (value >= 58) {
                mod = value % 58;
                reverse_str[i] = BASE58_ALPHABET[mod];
                value = value / 58;
                ++i;
        }

        reverse_str[i] = BASE58_ALPHABET[value];

        for (k = 0; k <= i; k++) {
                str[k] = reverse_str[i - k];
        }

        for (; k < BASE58_MAX_STR_SIZE; k++) {
                str[k] = '\0';
        }
}

// dissector function for dissecting TCP payloads
static void
dissect_protoTF_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	byte_offset = 0;
	bit_offset = 48;
	col_set_str(pinfo->cinfo, COL_PROTOCOL, &protoTF_proto_name_tcp[0]);	
	col_set_str(pinfo->cinfo, COL_INFO, &protoTF_proto_name[0]);

	// call for details
	if (tree)
	{ 
		proto_item *ti = NULL;
        	ti = proto_tree_add_item(tree, proto_protoTF, tvb, 0, -1, ENC_NA);
		protoTF_tree = proto_item_add_subtree(ti, ett_protoTF);

		base58_encode((uint32_t)tvb_get_letohl(tvb, 0),
			      &protoTF_uid_string[0]);

        	proto_tree_add_string(protoTF_tree,
				      hf_protoTF_uid_string,
 				      tvb, byte_offset, byte_count_protoTF_uid,
                                      &protoTF_uid_string[0]);

        	proto_tree_add_item(protoTF_tree,
				    hf_protoTF_uid_numeric,
                                    tvb,
                                    byte_offset,
                                    byte_count_protoTF_uid,
                                    ENC_BIG_ENDIAN);
		
		byte_offset += byte_count_protoTF_uid;

        	proto_tree_add_item(protoTF_tree,
				    hf_protoTF_length,
				    tvb,
				    byte_offset,
				    byte_count_protoTF_length,
				    ENC_BIG_ENDIAN);
		
		byte_offset += byte_count_protoTF_length;

        	proto_tree_add_item(protoTF_tree,
				    hf_protoTF_function_id,
     				    tvb,
				    byte_offset,
				    byte_count_protoTF_function_id,
				    ENC_BIG_ENDIAN);
		
		byte_offset += byte_count_protoTF_function_id;

        	proto_tree_add_bits_item(protoTF_tree,
					 hf_protoTF_sequence_number,
					 tvb,
					 bit_offset,
					 bit_count_protoTF_sequence_number,
					 ENC_BIG_ENDIAN);

		bit_offset += bit_count_protoTF_sequence_number;

        	proto_tree_add_bits_item(protoTF_tree,
					 hf_protoTF_R,
					 tvb,
					 bit_offset,
					 bit_count_protoTF_R,
					 ENC_BIG_ENDIAN);
		
		bit_offset += bit_count_protoTF_R;

        	proto_tree_add_bits_item(protoTF_tree,
					 hf_protoTF_A,
					 tvb,
					 bit_offset,
					 bit_count_protoTF_A,
					 ENC_BIG_ENDIAN);
		
		bit_offset += bit_count_protoTF_A;

        	proto_tree_add_bits_item(protoTF_tree,
					 hf_protoTF_OO,
					 tvb,
					 bit_offset,
					 bit_count_protoTF_OO,
					 ENC_BIG_ENDIAN);

		bit_offset += bit_count_protoTF_OO;

        	proto_tree_add_bits_item(protoTF_tree,
					 hf_protoTF_E,
					 tvb,
					 bit_offset,
					 bit_count_protoTF_E,
					 ENC_BIG_ENDIAN);
		
		bit_offset += bit_count_protoTF_E;

        	proto_tree_add_bits_item(protoTF_tree,
					 hf_protoTF_future_use,
					 tvb,
					 bit_offset,
					 bit_count_protoTF_future_use,
					 ENC_BIG_ENDIAN);

		bit_offset += bit_count_protoTF_future_use;

		if((tvb_length(tvb)) > 8){

			byte_offset += byte_count_protoTF_flags;
        			
			proto_tree_add_item(protoTF_tree,
				    	    hf_protoTF_data,
				    	    tvb,
				    	    byte_offset,
				    	    byte_count_protoTF_data,
				    	    ENC_NA);
		}
    	}
}

// dissector function for dissecting USB payloads
static void
dissect_protoTF_usb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	usb_conv_info_t *usb_conv_info;
	usb_conv_info = (usb_conv_info_t *)pinfo->usb_conv_info;

	if((usb_conv_info->deviceVendor == protoTF_USB_VENDOR_ID) && (usb_conv_info->deviceProduct == protoTF_USB_PRODUCT_ID))
	{
		byte_offset = 0;
		bit_offset = 48;
		col_set_str(pinfo->cinfo, COL_PROTOCOL, &protoTF_proto_name_usb[0]);	
		col_set_str(pinfo->cinfo, COL_INFO, &protoTF_proto_name[0]);

		// call for details
		if (tree)
		{ 
			proto_item *ti = NULL;
        		ti = proto_tree_add_item(tree, proto_protoTF, tvb, 0, -1, ENC_NA);
			protoTF_tree = proto_item_add_subtree(ti, ett_protoTF);

			base58_encode((uint32_t)tvb_get_letohl(tvb, 0),
			      	      &protoTF_uid_string[0]);

        		proto_tree_add_string(protoTF_tree,
				      	      hf_protoTF_uid_string,
 				      	      tvb, byte_offset, byte_count_protoTF_uid,
                                      	      &protoTF_uid_string[0]);

        		proto_tree_add_item(protoTF_tree,
				    	    hf_protoTF_uid_numeric,
				    	    tvb,
				    	    byte_offset,
				    	    byte_count_protoTF_uid,
				    	    ENC_BIG_ENDIAN);
		
			byte_offset += byte_count_protoTF_uid;

        		proto_tree_add_item(protoTF_tree,
				    	    hf_protoTF_length,
				    	    tvb,
				    	    byte_offset,
				    	    byte_count_protoTF_length,
				    	    ENC_BIG_ENDIAN);
		
			byte_offset += byte_count_protoTF_length;

        		proto_tree_add_item(protoTF_tree,
				    	    hf_protoTF_function_id,
				    	    tvb,
				    	    byte_offset,
				    	    byte_count_protoTF_function_id,
				    	    ENC_BIG_ENDIAN);
		
			byte_offset += byte_count_protoTF_function_id;

        		proto_tree_add_bits_item(protoTF_tree,
				    	    hf_protoTF_sequence_number,
				    	    tvb,
				    	    bit_offset,
				    	    bit_count_protoTF_sequence_number,
				    	    ENC_BIG_ENDIAN);

			bit_offset += bit_count_protoTF_sequence_number;

        		proto_tree_add_bits_item(protoTF_tree,
				    	   	 hf_protoTF_R,
				    	   	 tvb,
				    	   	 bit_offset,
				    	   	 bit_count_protoTF_R,
				    	   	 ENC_BIG_ENDIAN);
		
			bit_offset += bit_count_protoTF_R;

        		proto_tree_add_bits_item(protoTF_tree,
					 	 hf_protoTF_A,
					 	 tvb,
					 	 bit_offset,
					 	 bit_count_protoTF_A,
					 	 ENC_BIG_ENDIAN);
		
			bit_offset += bit_count_protoTF_A;

        		proto_tree_add_bits_item(protoTF_tree,
					 	 hf_protoTF_OO,
					 	 tvb,
					 	 bit_offset,
					 	 bit_count_protoTF_OO,
					 	 ENC_BIG_ENDIAN);

			bit_offset += bit_count_protoTF_OO;

        		proto_tree_add_bits_item(protoTF_tree,
					 	 hf_protoTF_E,
					 	 tvb,
					 	 bit_offset,
					 	 bit_count_protoTF_E,
					 	 ENC_BIG_ENDIAN);
		
			bit_offset += bit_count_protoTF_E;

        		proto_tree_add_bits_item(protoTF_tree,
					 	 hf_protoTF_future_use,
					 	 tvb,
					 	 bit_offset,
					 	 bit_count_protoTF_future_use,
					 	 ENC_BIG_ENDIAN);

			bit_offset += bit_count_protoTF_future_use;

		
			if((tvb_length(tvb)) > 8){

				byte_offset += byte_count_protoTF_flags;
        			
				proto_tree_add_item(protoTF_tree,
				    	    	    hf_protoTF_data,
				    	    	    tvb,
				    	     	    byte_offset,
				    	    	    byte_count_protoTF_data,
				    	    	    ENC_NA);
			}
    		}
	}
}

// dissector function for dissecting UDP payloads
static void
dissect_protoTF_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	byte_offset = 0;
	bit_offset = 48;
	col_set_str(pinfo->cinfo, COL_PROTOCOL, &protoTF_proto_name_udp[0]);	
	col_set_str(pinfo->cinfo, COL_INFO, &protoTF_proto_name[0]);

	// call for details
	if (tree)
	{ 
		proto_item *ti = NULL;
        	ti = proto_tree_add_item(tree, proto_protoTF, tvb, 0, -1, ENC_NA);
		protoTF_tree = proto_item_add_subtree(ti, ett_protoTF);

		base58_encode((uint32_t)tvb_get_letohl(tvb, 0),
			      &protoTF_uid_string[0]);

        	proto_tree_add_string(protoTF_tree,
				      hf_protoTF_uid_string,
 				      tvb, byte_offset, byte_count_protoTF_uid,
                                      &protoTF_uid_string[0]);

        	proto_tree_add_item(protoTF_tree,
				    hf_protoTF_uid_numeric,
                                    tvb,
                                    byte_offset,
                                    byte_count_protoTF_uid,
                                    ENC_BIG_ENDIAN);
		
		byte_offset += byte_count_protoTF_uid;

        	proto_tree_add_item(protoTF_tree,
				    hf_protoTF_length,
				    tvb,
				    byte_offset,
				    byte_count_protoTF_length,
				    ENC_BIG_ENDIAN);
		
		byte_offset += byte_count_protoTF_length;

        	proto_tree_add_item(protoTF_tree,
				    hf_protoTF_function_id,
     				    tvb,
				    byte_offset,
				    byte_count_protoTF_function_id,
				    ENC_BIG_ENDIAN);
		
		byte_offset += byte_count_protoTF_function_id;

        	proto_tree_add_bits_item(protoTF_tree,
					 hf_protoTF_sequence_number,
					 tvb,
					 bit_offset,
					 bit_count_protoTF_sequence_number,
					 ENC_BIG_ENDIAN);

		bit_offset += bit_count_protoTF_sequence_number;

        	proto_tree_add_bits_item(protoTF_tree,
					 hf_protoTF_R,
					 tvb,
					 bit_offset,
					 bit_count_protoTF_R,
					 ENC_BIG_ENDIAN);
		
		bit_offset += bit_count_protoTF_R;

        	proto_tree_add_bits_item(protoTF_tree,
					 hf_protoTF_A,
					 tvb,
					 bit_offset,
					 bit_count_protoTF_A,
					 ENC_BIG_ENDIAN);
		
		bit_offset += bit_count_protoTF_A;

        	proto_tree_add_bits_item(protoTF_tree,
					 hf_protoTF_OO,
					 tvb,
					 bit_offset,
					 bit_count_protoTF_OO,
					 ENC_BIG_ENDIAN);

		bit_offset += bit_count_protoTF_OO;

        	proto_tree_add_bits_item(protoTF_tree,
					 hf_protoTF_E,
					 tvb,
					 bit_offset,
					 bit_count_protoTF_E,
					 ENC_BIG_ENDIAN);
		
		bit_offset += bit_count_protoTF_E;

        	proto_tree_add_bits_item(protoTF_tree,
					 hf_protoTF_future_use,
					 tvb,
					 bit_offset,
					 bit_count_protoTF_future_use,
					 ENC_BIG_ENDIAN);

		bit_offset += bit_count_protoTF_future_use;

		if((tvb_length(tvb)) > 8){

			byte_offset += byte_count_protoTF_flags;
        			
			proto_tree_add_item(protoTF_tree,
				    	    hf_protoTF_data,
				    	    tvb,
				    	    byte_offset,
				    	    byte_count_protoTF_data,
				    	    ENC_NA);
		}
    	}
}

// protocol register function
void
proto_register_protoTF(void)
{
	// defining header formats
	static hf_register_info hf_protoTF[] = {
      		{ &hf_protoTF_uid_string,
            		{ "UID(String) @ 1st 4 Bytes",
	  	    	  "protoTF.uid_string",
            	          FT_STRINGZ,
			  BASE_NONE,
            	          NULL,
		          0x0,
            	          NULL,
		          HFILL
		  	}
        	},
        	{ &hf_protoTF_uid_numeric,
            		{ "UID(Numeric) @ 1st 4 Bytes",
	  	    	  "protoTF.uid_numeric",
            	          FT_UINT32,
			  BASE_DEC,
            	          NULL,
		          0x0,
            	          NULL,
		          HFILL
		  	}
        	},
        	{ &hf_protoTF_length,
            		{ "Length @ 5th Byte",
	  	    	  "protoTF.length",
            	          FT_UINT8,
			  BASE_DEC,
            	          NULL,
		          0x0,
            	          NULL,
		          HFILL
		  	}
        	},
        	{ &hf_protoTF_function_id,
            		{ "Function ID @ 6th Byte",
	  	    	  "protoTF.function_id",
            	          FT_UINT8,
			  BASE_DEC,
            	          NULL,
		          0x0,
            	          NULL,
		          HFILL
		  	}
        	},
        	{ &hf_protoTF_sequence_number,
            		{ "Sequence Number(4-bits) @ 7th Byte",
	  	    	  "protoTF.sequence_number",
            	          FT_UINT8,
			  BASE_DEC,
            	          NULL,
		          0x0,
            	          NULL,
		          HFILL
		  	}
        	},
        	{ &hf_protoTF_R,
            		{ "R(1-bit) @ 7th Byte",
	  	    	  "protoTF.R",
            	          FT_UINT8,
			  BASE_DEC,
            	          NULL,
		          0x0,
            	          NULL,
		          HFILL
		  	}
        	},
        	{ &hf_protoTF_A,
            		{ "A(1-bit) @ 7th Byte",
	  	    	  "protoTF.A",
            	          FT_UINT8,
			  BASE_DEC,
            	          NULL,
		          0x0,
            	          NULL,
		          HFILL
		  	}
        	},
        	{ &hf_protoTF_OO,
            		{ "OO(2-bits) @ 7th Byte",
	  	    	  "protoTF.OO",
            	          FT_UINT8,
			  BASE_DEC,
            	          NULL,
		          0x0,
            	          NULL,
		          HFILL
		  	}
        	},
        	{ &hf_protoTF_E,
            		{ "E(2-bits) @ 8th Byte",
	  	    	  "protoTF.E",
            	          FT_UINT8,
			  BASE_DEC,
            	          NULL,
		          0x0,
            	          NULL,
		          HFILL
		  	}
        	},
        	{ &hf_protoTF_future_use,
            		{ "Future Use(6-bits) @ 8th Byte",
	  	    	  "protoTF.future_use",
            	          FT_UINT8,
			  BASE_DEC,
            	          NULL,
		          0x0,
            	          NULL,
		          HFILL
		  	}
        	},
		{ &hf_protoTF_data,
            		{ "Data",
	  	    	  "protoTF.Data",
            	          FT_BYTES,
			  BASE_NONE,
            	          NULL,
		          0x0,
            	          NULL,
		          HFILL
		  	}
        	}
    	};

	// setup protocol subtree array
	static gint *ett[] = {
        	&ett_protoTF
	};

	// defining the protocol and its names
	proto_protoTF = proto_register_protocol (
		"TinkerForge Protocol",
        	"proto_tf",
        	"proto_tf"
	);

	proto_register_field_array(proto_protoTF, hf_protoTF, array_length(hf_protoTF));
	proto_register_subtree_array(ett, array_length(ett));
}

// handoff function
void
proto_reg_handoff_protoTF(void){

	static dissector_handle_t 
	protoTF_handle_tcp,
	protoTF_handle_udp,
	protoTF_handle_usb;

	protoTF_handle_tcp = create_dissector_handle(dissect_protoTF_tcp, proto_protoTF);
	protoTF_handle_udp = create_dissector_handle(dissect_protoTF_udp, proto_protoTF);
	protoTF_handle_usb = create_dissector_handle(dissect_protoTF_usb, proto_protoTF);

	dissector_add_uint("tcp.port", protoTF_PORT, protoTF_handle_tcp);
	dissector_add_uint("udp.port", protoTF_PORT, protoTF_handle_udp);
	dissector_add_uint("usb.bulk", IF_CLASS_VENDOR_SPECIFIC, protoTF_handle_usb);
}

