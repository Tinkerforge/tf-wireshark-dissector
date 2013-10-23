/* packet-tfp.c
 * Routines for Tinkerforge protocol packet disassembly
 * By Ishraq Ibne Ashraf <ishraq@tinkerforge.com>
 * Copyright 2013 Ishraq Ibne Ashraf
 *
 * $Id: packet-tfp.c 48634 2013-03-29 00:26:23Z eapache $
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
#define tfp_PORT 4223
#define tfp_USB_VENDOR_ID 0x16D0
#define tfp_USB_PRODUCT_ID 0x063D
#define BASE58_MAX_STR_SIZE 13

// protocol naming strings
static const char *tfp_proto_name = "Tinkerforge Protocol";
static const char *tfp_proto_name_tcp = "tfp tcp";
static const char *tfp_proto_name_usb = "tfp usb";

// variables for creating the tree
static int proto_tfp = -1;
static gint ett_tfp = -1;
static proto_tree *tfp_tree = NULL;

// header field variables
static int hf_tfp_uid = -1;
static int hf_tfp_uid_numeric = -1;
static int hf_tfp_len = -1;
static int hf_tfp_fid = -1;
static int hf_tfp_seq = -1;
static int hf_tfp_r = -1;
static int hf_tfp_a = -1;
static int hf_tfp_oo = -1;
static int hf_tfp_e = -1;
static int hf_tfp_future_use = -1;
static int hf_tfp_payload = -1;

// bit and byte offsets for dissection
static gint byte_offset = 0;
static gint byte_count_tfp_uid = 4;
static gint byte_count_tfp_len = 1;
static gint byte_count_tfp_fid = 1;
static gint byte_count_tfp_flags = 2;
static gint byte_count_tfp_payload = -1;
static gint bit_offset = 48;
static gint bit_count_tfp_seq = 4;
static gint bit_count_tfp_r = 1;
static gint bit_count_tfp_a = 1;
static gint bit_count_tfp_oo = 2;
static gint bit_count_tfp_e = 2;
static gint bit_count_tfp_future_use = 6;

// base58 encoding variables
static char tfp_uid_string[BASE58_MAX_STR_SIZE];
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
dissect_tfp_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	byte_offset = 0;
	bit_offset = 48;
	col_set_str(pinfo->cinfo, COL_PROTOCOL, &tfp_proto_name_tcp[0]);	
	col_set_str(pinfo->cinfo, COL_INFO, &tfp_proto_name[0]);

	// call for details
	if (tree)
	{ 
		proto_item *ti = NULL;
        	ti = proto_tree_add_item(tree, proto_tfp, tvb, 0, -1, ENC_NA);
		tfp_tree = proto_item_add_subtree(ti, ett_tfp);

		base58_encode((uint32_t)tvb_get_letohl(tvb, 0),
			      &tfp_uid_string[0]);

        	proto_tree_add_string(tfp_tree,
				      hf_tfp_uid,
 				      tvb, byte_offset, byte_count_tfp_uid,
                                      &tfp_uid_string[0]);

        	proto_tree_add_item(tfp_tree,
				    hf_tfp_uid_numeric,
                                    tvb,
                                    byte_offset,
                                    byte_count_tfp_uid,
                                    ENC_BIG_ENDIAN);
		
		byte_offset += byte_count_tfp_uid;

        	proto_tree_add_item(tfp_tree,
				    hf_tfp_len,
				    tvb,
				    byte_offset,
				    byte_count_tfp_len,
				    ENC_BIG_ENDIAN);
		
		byte_offset += byte_count_tfp_len;

        	proto_tree_add_item(tfp_tree,
				    hf_tfp_fid,
     				    tvb,
				    byte_offset,
				    byte_count_tfp_fid,
				    ENC_BIG_ENDIAN);
		
		byte_offset += byte_count_tfp_fid;

        	proto_tree_add_bits_item(tfp_tree,
					 hf_tfp_seq,
					 tvb,
					 bit_offset,
					 bit_count_tfp_seq,
					 ENC_BIG_ENDIAN);

		bit_offset += bit_count_tfp_seq;

        	proto_tree_add_bits_item(tfp_tree,
					 hf_tfp_r,
					 tvb,
					 bit_offset,
					 bit_count_tfp_r,
					 ENC_BIG_ENDIAN);
		
		bit_offset += bit_count_tfp_r;

        	proto_tree_add_bits_item(tfp_tree,
					 hf_tfp_a,
					 tvb,
					 bit_offset,
					 bit_count_tfp_a,
					 ENC_BIG_ENDIAN);
		
		bit_offset += bit_count_tfp_a;

        	proto_tree_add_bits_item(tfp_tree,
					 hf_tfp_oo,
					 tvb,
					 bit_offset,
					 bit_count_tfp_oo,
					 ENC_BIG_ENDIAN);

		bit_offset += bit_count_tfp_oo;

        	proto_tree_add_bits_item(tfp_tree,
					 hf_tfp_e,
					 tvb,
					 bit_offset,
					 bit_count_tfp_e,
					 ENC_BIG_ENDIAN);
		
		bit_offset += bit_count_tfp_e;

        	proto_tree_add_bits_item(tfp_tree,
					 hf_tfp_future_use,
					 tvb,
					 bit_offset,
					 bit_count_tfp_future_use,
					 ENC_BIG_ENDIAN);

		bit_offset += bit_count_tfp_future_use;

		if((tvb_length(tvb)) > 8){

			byte_offset += byte_count_tfp_flags;
        			
			proto_tree_add_item(tfp_tree,
				    	    hf_tfp_payload,
				    	    tvb,
				    	    byte_offset,
				    	    byte_count_tfp_payload,
				    	    ENC_NA);
		}
    	}
}

// dissector function for dissecting USB payloads
static void
dissect_tfp_usb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	usb_conv_info_t *usb_conv_info;
	usb_conv_info = (usb_conv_info_t *)pinfo->usb_conv_info;

	if((usb_conv_info->deviceVendor == tfp_USB_VENDOR_ID) && (usb_conv_info->deviceProduct == tfp_USB_PRODUCT_ID))
	{
		byte_offset = 0;
		bit_offset = 48;
		col_set_str(pinfo->cinfo, COL_PROTOCOL, &tfp_proto_name_usb[0]);	
		col_set_str(pinfo->cinfo, COL_INFO, &tfp_proto_name[0]);

		// call for details
		if (tree)
		{ 
			proto_item *ti = NULL;
        		ti = proto_tree_add_item(tree, proto_tfp, tvb, 0, -1, ENC_NA);
			tfp_tree = proto_item_add_subtree(ti, ett_tfp);

			base58_encode((uint32_t)tvb_get_letohl(tvb, 0),
			      	      &tfp_uid_string[0]);

        		proto_tree_add_string(tfp_tree,
				      	      hf_tfp_uid,
 				      	      tvb, byte_offset, byte_count_tfp_uid,
                                      	      &tfp_uid_string[0]);

        		proto_tree_add_item(tfp_tree,
				    	    hf_tfp_uid_numeric,
				    	    tvb,
				    	    byte_offset,
				    	    byte_count_tfp_uid,
				    	    ENC_BIG_ENDIAN);
		
			byte_offset += byte_count_tfp_uid;

        		proto_tree_add_item(tfp_tree,
				    	    hf_tfp_len,
				    	    tvb,
				    	    byte_offset,
				    	    byte_count_tfp_len,
				    	    ENC_BIG_ENDIAN);
		
			byte_offset += byte_count_tfp_len;

        		proto_tree_add_item(tfp_tree,
				    	    hf_tfp_fid,
				    	    tvb,
				    	    byte_offset,
				    	    byte_count_tfp_fid,
				    	    ENC_BIG_ENDIAN);
		
			byte_offset += byte_count_tfp_fid;

        		proto_tree_add_bits_item(tfp_tree,
				    	    hf_tfp_seq,
				    	    tvb,
				    	    bit_offset,
				    	    bit_count_tfp_seq,
				    	    ENC_BIG_ENDIAN);

			bit_offset += bit_count_tfp_seq;

        		proto_tree_add_bits_item(tfp_tree,
				    	   	 hf_tfp_r,
				    	   	 tvb,
				    	   	 bit_offset,
				    	   	 bit_count_tfp_r,
				    	   	 ENC_BIG_ENDIAN);
		
			bit_offset += bit_count_tfp_r;

        		proto_tree_add_bits_item(tfp_tree,
					 	 hf_tfp_a,
					 	 tvb,
					 	 bit_offset,
					 	 bit_count_tfp_a,
					 	 ENC_BIG_ENDIAN);
		
			bit_offset += bit_count_tfp_a;

        		proto_tree_add_bits_item(tfp_tree,
					 	 hf_tfp_oo,
					 	 tvb,
					 	 bit_offset,
					 	 bit_count_tfp_oo,
					 	 ENC_BIG_ENDIAN);

			bit_offset += bit_count_tfp_oo;

        		proto_tree_add_bits_item(tfp_tree,
					 	 hf_tfp_e,
					 	 tvb,
					 	 bit_offset,
					 	 bit_count_tfp_e,
					 	 ENC_BIG_ENDIAN);
		
			bit_offset += bit_count_tfp_e;

        		proto_tree_add_bits_item(tfp_tree,
					 	 hf_tfp_future_use,
					 	 tvb,
					 	 bit_offset,
					 	 bit_count_tfp_future_use,
					 	 ENC_BIG_ENDIAN);

			bit_offset += bit_count_tfp_future_use;

		
			if((tvb_length(tvb)) > 8){

				byte_offset += byte_count_tfp_flags;
        			
				proto_tree_add_item(tfp_tree,
				    	    	    hf_tfp_payload,
				    	    	    tvb,
				    	     	    byte_offset,
				    	    	    byte_count_tfp_payload,
				    	    	    ENC_NA);
			}
    		}
	}
}

// protocol register function
void
proto_register_tfp(void)
{
	// defining header formats
	static hf_register_info hf_tfp[] = {
      		{ &hf_tfp_uid,
            		{ "UID (String)",
	  	    	  "tfp.uid",
            	          FT_STRINGZ,
			  BASE_NONE,
            	          NULL,
		          0x0,
            	          NULL,
		          HFILL
		  	}
        	},
        	{ &hf_tfp_uid_numeric,
            		{ "UID (Numeric)",
	  	    	  "tfp.uid_numeric",
            	          FT_UINT32,
			  BASE_DEC,
            	          NULL,
		          0x0,
            	          NULL,
		          HFILL
		  	}
        	},
        	{ &hf_tfp_len,
            		{ "Length",
	  	    	  "tfp.len",
            	          FT_UINT8,
			  BASE_DEC,
            	          NULL,
		          0x0,
            	          NULL,
		          HFILL
		  	}
        	},
        	{ &hf_tfp_fid,
            		{ "Function ID",
	  	    	  "tfp.fid",
            	          FT_UINT8,
			  BASE_DEC,
            	          NULL,
		          0x0,
            	          NULL,
		          HFILL
		  	}
        	},
        	{ &hf_tfp_seq,
            		{ "Sequence Number",
	  	    	  "tfp.seq",
            	          FT_UINT8,
			  BASE_DEC,
            	          NULL,
		          0x0,
            	          NULL,
		          HFILL
		  	}
        	},
        	{ &hf_tfp_r,
            		{ "Response Expected",
	  	    	  "tfp.r",
            	          FT_UINT8,
			  BASE_DEC,
            	          NULL,
		          0x0,
            	          NULL,
		          HFILL
		  	}
        	},
        	{ &hf_tfp_a,
            		{ "Authentication",
	  	    	  "tfp.a",
            	          FT_UINT8,
			  BASE_DEC,
            	          NULL,
		          0x0,
            	          NULL,
		          HFILL
		  	}
        	},
        	{ &hf_tfp_oo,
            		{ "Other Options",
	  	    	  "tfp.oo",
            	          FT_UINT8,
			  BASE_DEC,
            	          NULL,
		          0x0,
            	          NULL,
		          HFILL
		  	}
        	},
        	{ &hf_tfp_e,
            		{ "Error Code",
	  	    	  "tfp.e",
            	          FT_UINT8,
			  BASE_DEC,
            	          NULL,
		          0x0,
            	          NULL,
		          HFILL
		  	}
        	},
        	{ &hf_tfp_future_use,
            		{ "Future Use",
	  	    	  "tfp.future_use",
            	          FT_UINT8,
			  BASE_DEC,
            	          NULL,
		          0x0,
            	          NULL,
		          HFILL
		  	}
        	},
		{ &hf_tfp_payload,
            		{ "Payload",
	  	    	  "tfp.payload",
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
        	&ett_tfp
	};

	// defining the protocol and its names
	proto_tfp = proto_register_protocol (
		"Tinkerforge Protocol",
		"TFP",
        "tfp"
	);

	proto_register_field_array(proto_tfp, hf_tfp, array_length(hf_tfp));
	proto_register_subtree_array(ett, array_length(ett));
}

// handoff function
void
proto_reg_handoff_tfp(void){

	static dissector_handle_t 
	tfp_handle_tcp,
	tfp_handle_usb;

	tfp_handle_tcp = create_dissector_handle(dissect_tfp_tcp, proto_tfp);
	tfp_handle_usb = create_dissector_handle(dissect_tfp_usb, proto_tfp);

	dissector_add_uint("tcp.port", tfp_PORT, tfp_handle_tcp);
	dissector_add_uint("usb.bulk", IF_CLASS_VENDOR_SPECIFIC, tfp_handle_usb);
}

