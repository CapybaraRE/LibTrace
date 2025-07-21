#pragma once

#include <sstream>

#include "Zydis/Zydis.h"

class CDisassembler
{
public:
    static auto GetSignature(const std::uint8_t* pCode, const size_t codeSize, std::string& pattern, const bool bIsX64) -> void
    {
        AnalyzeFuncGenerateSignature(pCode, codeSize, pattern, bIsX64);
    }
private:
    static auto AnalyzeFuncGenerateSignature(const std::uint8_t* pCode, const size_t codeSize, std::string& pattern, const bool bIsX64) -> void
    {
        ZydisMachineMode machineMode = bIsX64 ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LEGACY_32;
        ZydisStackWidth addressWidth = bIsX64 ? ZYDIS_STACK_WIDTH_64 : ZYDIS_STACK_WIDTH_32;

        ZydisDecoder decoder                = {};
        ZydisDecodedInstruction instruction = {};

        ZyanUSize offset = 0;

        std::stringstream signatureStream = {};
        
        ZydisDecoderInit(&decoder, machineMode, addressWidth);

        while (offset < codeSize && ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(&decoder, nullptr, pCode + offset, codeSize - offset, &instruction)))
        {
            if (offset > 0)
            {
                signatureStream << " ";
            }

            const bool isRelative = instruction.attributes & ZYDIS_ATTRIB_IS_RELATIVE;
            
            ZyanU8 relativeOperandOffset = {};
            ZyanU8 relativeOperandSize   = {};
            
            if (isRelative)
            {
                if (instruction.raw.imm[0].is_relative)
                {
                    relativeOperandOffset   = instruction.raw.imm[0].offset;
                    relativeOperandSize     = instruction.raw.imm[0].size / 8;
                }
                else if (instruction.raw.disp.size > 0)
                {
                    relativeOperandOffset   = instruction.raw.disp.offset;
                    relativeOperandSize     = instruction.raw.disp.size / 8;
                }
            }

            for (ZyanU8 i = 0; i < instruction.length; ++i)
            {
                auto isWildcardByte = false;
                if (isRelative && relativeOperandSize > 0 && i >= relativeOperandOffset && i < relativeOperandOffset + relativeOperandSize)
                {
                    isWildcardByte = true;
                }

                if (isWildcardByte)
                {
                    signatureStream << "??";
                }
                else
                {
                    signatureStream << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(pCode[offset + i]);
                }

                if (i < instruction.length - 1)
                {
                    signatureStream << " ";
                }
            }

            offset += instruction.length;
        }

        pattern = signatureStream.str();
    }
};