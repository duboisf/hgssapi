{-# LANGUAGE ForeignFunctionInterface #-}
module Security.GSSAPI where

import Control.Monad (ap)
import Data.Word (Word32)
import Foreign.C.Types
import Foreign.Ptr
import Foreign.Storable

#include <gssapi/gssapi.h>

#let alignment t = "%lu", (unsigned long)offsetof(struct {char x__; t (y__); }, y__)

{-
 - types
 -}
data Buffer = Buffer {
    bLength :: CSize
  , bValue :: Ptr ()
  }

data OIDDesc = OIDDesc {
    oidLength :: CUInt
  , oidElements :: Ptr ()
  }

instance Storable OIDDesc where
  alignment _ = #{alignment gss_OID_desc}
  sizeOf _ = #{size gss_OID_desc}
  peek ptr = return OIDDesc
    `ap` (#{peek gss_OID_desc, length} ptr)
    `ap` (#{peek gss_OID_desc, elements} ptr)
  poke ptr (OIDDesc len elems) = do
    #{poke gss_OID_desc, length} ptr len
    #{poke gss_OID_desc, elements} ptr elems

newtype Name = Name (Ptr Name)

foreign import ccall "&GSS_C_NT_HOSTBASED_SERVICE"
  c_gss_c_nt_hostbased_service :: Ptr (Ptr OIDDesc)

gss_c_nt_hostbased_service :: IO (Ptr OIDDesc)
gss_c_nt_hostbased_service =
  peek c_gss_c_nt_hostbased_service

foreign import ccall
  gss_import_name :: CUInt -> Ptr Buffer -> Ptr OIDDesc -> Ptr Name -> CUInt

-- vim: ft=haskell
