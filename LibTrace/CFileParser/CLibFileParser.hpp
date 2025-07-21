#pragma once

#include <algorithm>
#include <array>
#include <charconv>
#include <filesystem>
#include <fstream>
#include <ranges>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>
#include <Windows.h>

#include "CDisassembler/CDisassembler.hpp"
#include "CLogger/CLogger.hpp"
#include "Json/Json.hpp"
#include "CThreadPool/CThreadPool.hpp"

class CLibFileParser
{
public:
    static auto ParseFile(const std::filesystem::path& file, const std::filesystem::path& output) -> void
    {
        namespace fs = std::filesystem;
        
        auto RemoveSpaces = [](std::string_view s) -> std::string_view
        {
            const auto it = std::ranges::find_if(std::ranges::reverse_view(s), [](const unsigned char ch){ return !std::isspace(ch); });

            s.remove_suffix(std::distance(s.rbegin(), it));

            return s;
        };

        const auto& outputPath = output;
        
        CLogger::Log("Parsing file -> {} <-.\n", file.string());

        std::ifstream in(file, std::ios::binary);
        if (!in.is_open())
        {
            CLogger::Log("Failed to open file. Check file name or file path.\n");
            
            return;
        }

        const auto fileType             = GetFileType(in);
        const auto fileTypeStr  = GetFileTypeAsStr(fileType);
        const auto fileSize     = fs::file_size(file);

        CLogger::Log("File size -> {} <-.\n", fileSize);
        CLogger::Log("File type -> {} <-.\n", fileTypeStr.c_str());

        if (fileType == eFileTypes::UNK_FILE_TYPE)
        {
            CLogger::Log("Wrong file type.\n");
            
            return;
        }
        
        if (fileSize < IMAGE_ARCHIVE_START_SIZE)
        {
            CLogger::Log("File is too small to be a valid library.\n");
            
            return;
        }
        
        std::vector<char> buffer(fileSize);
        in.read(buffer.data(), static_cast<std::streamsize>(fileSize));
        
        const auto memStart = buffer.data();
        const auto memEnd   = memStart + fileSize;
        
        auto pCurrentMemberHeader = reinterpret_cast<ArchiveMemberHeader*>(memStart + IMAGE_ARCHIVE_START_SIZE);

        nlohmann::json signaturesJson;
        
        CThreadPool pool(std::thread::hardware_concurrency());
        std::vector<std::future<nlohmann::json>> results;

        std::atomic_uint32_t totalFunctionsParsed = 0;
        while (reinterpret_cast<char*>(pCurrentMemberHeader) + ARCHIVE_MEMBER_HEADER_SIZE <= memEnd)
        {
            std::size_t size = 0;
            const auto sizeSV = RemoveSpaces({pCurrentMemberHeader->Size, sizeof(pCurrentMemberHeader->Size)});
            if (auto [ptr, ec] = std::from_chars(sizeSV.data(), sizeSV.data() + sizeSV.size(), size); ec != std::errc{})
            {
                CLogger::Log("Invalid member size. Stopping parse.\n");
                
                break;
            }
            
            auto pNextHeader = reinterpret_cast<char*>(pCurrentMemberHeader) + ARCHIVE_MEMBER_HEADER_SIZE + size;
            
            pNextHeader += size % 2; // Padding.
            
            if (pNextHeader > memEnd)
            {
                CLogger::Log("Member size is invalid, leads out of file bounds. Stopping.\n");
                
                break;
            }

            const std::string_view headerNameView(pCurrentMemberHeader->Name, sizeof(pCurrentMemberHeader->Name));
            if (headerNameView == IMAGE_ARCHIVE_LINKER_MEMBER || headerNameView == IMAGE_ARCHIVE_LONGNAMES_MEMBER)
            {
                pCurrentMemberHeader = reinterpret_cast<ArchiveMemberHeader*>(pNextHeader);
                
                continue;
            }
            
            if (size < sizeof(IMAGE_FILE_HEADER))
            {
                pCurrentMemberHeader = reinterpret_cast<ArchiveMemberHeader*>(pNextHeader);
                
                continue;
            }
            
            const auto pMemberData  = reinterpret_cast<const char*>(pCurrentMemberHeader) + ARCHIVE_MEMBER_HEADER_SIZE;
            const auto pFileHeader            = reinterpret_cast<const IMAGE_FILE_HEADER*>(pMemberData);

            if (pFileHeader->Machine != IMAGE_FILE_MACHINE_I386 && pFileHeader->Machine != IMAGE_FILE_MACHINE_AMD64)
            {
                pCurrentMemberHeader = reinterpret_cast<ArchiveMemberHeader*>(pNextHeader);
                
                continue;
            }
            
            if (pFileHeader->PointerToSymbolTable == 0 || pFileHeader->NumberOfSymbols == 0)
            {
                pCurrentMemberHeader = reinterpret_cast<ArchiveMemberHeader*>(pNextHeader);
                
                continue;
            }
            
            results.emplace_back(pool.enqueue([pMemberData, memEnd, RemoveSpaces, pFileHeader, &totalFunctionsParsed]
            {
                nlohmann::json localJson;
                
                const auto pSymbolTable     = reinterpret_cast<const IMAGE_SYMBOL*>(pMemberData + pFileHeader->PointerToSymbolTable);
                const auto pStringTable     = reinterpret_cast<const char*>(pSymbolTable + pFileHeader->NumberOfSymbols);
                const auto pSectionHeaders  = reinterpret_cast<const IMAGE_SECTION_HEADER*>(pMemberData + sizeof(IMAGE_FILE_HEADER) + pFileHeader->SizeOfOptionalHeader);
                
                std::unordered_map<std::uint16_t, std::vector<const IMAGE_SYMBOL*>> functionsBySection;
                
                for (std::uint32_t i = 0; i < pFileHeader->NumberOfSymbols; ++i)
                {
                    const auto& symbol = pSymbolTable[i];
                    if ((symbol.StorageClass == IMAGE_SYM_CLASS_EXTERNAL || symbol.StorageClass == IMAGE_SYM_CLASS_STATIC) && symbol.SectionNumber > IMAGE_SYM_UNDEFINED && ISFCN(symbol.Type) && std::cmp_less_equal(symbol.SectionNumber, pFileHeader->NumberOfSections))
                    {
                        if (const auto& section = pSectionHeaders[symbol.SectionNumber - 1]; section.Characteristics & IMAGE_SCN_CNT_CODE)
                        {
                            functionsBySection[symbol.SectionNumber].push_back(&symbol);
                        }
                    }
                    i += symbol.NumberOfAuxSymbols;
                }

                for (auto& [sectionIdx, funcSymbols] : functionsBySection)
                {
                    std::ranges::sort(funcSymbols, [](const IMAGE_SYMBOL* a, const IMAGE_SYMBOL* b){ return a->Value < b->Value; });
                    
                    const auto& section = pSectionHeaders[sectionIdx - 1];

                    for (size_t i = 0; i < funcSymbols.size(); ++i)
                    {
                        const auto* pSymbol = funcSymbols[i];
                        
                        std::size_t funcSize = 0;
                        if (i < funcSymbols.size() - 1)
                        {
                            funcSize = funcSymbols[i + 1]->Value - pSymbol->Value;
                        }
                        else
                        {
                            funcSize = section.SizeOfRawData - pSymbol->Value;
                        }
                        
                        std::string symbolName;
                        if (pSymbol->N.Name.Short == 0)
                        {
                            const auto pName = pStringTable + pSymbol->N.Name.Long;
                            symbolName = pName < memEnd ? pName : "[ERROR]";
                        }
                        else
                        {
                            symbolName = RemoveSpaces({reinterpret_cast<const char*>(pSymbol->N.ShortName), IMAGE_SIZEOF_SHORT_NAME});
                        }

                        if (symbolName.empty()) continue;

                        if (const auto pFuncCode = pMemberData + section.PointerToRawData + pSymbol->Value; pFuncCode + funcSize <= memEnd)
                        {
                            const auto pCode = reinterpret_cast<const std::uint8_t*>(pFuncCode);

                            CLogger::Log("Generating signature for -> {} <-. Size -> {} <-.\n", symbolName.c_str(), funcSize);
                            
                            std::string pattern;
                            
                            CDisassembler::GetSignature(pCode, funcSize, pattern, pFileHeader->Machine == IMAGE_FILE_MACHINE_AMD64);
                            ++totalFunctionsParsed;
                            
                            localJson[symbolName] = pattern;

                            CLogger::Log("Func -> {} <-. Signature -> {} <-.\n",symbolName.c_str(), pattern.c_str());
                        }
                    }
                }
                return localJson;
            }));
            
            pCurrentMemberHeader = reinterpret_cast<ArchiveMemberHeader*>(pNextHeader);
        }
        
        for(auto& future : results)
        {
            signaturesJson.update(future.get());
        }
        std::string out = (outputPath / "Signatures.json").generic_string();
        
        std::ofstream o(out);
        o << std::setw(4) << signaturesJson << '\n';
        o.close();

        CLogger::Log("Parsed -> {} <- functions.", totalFunctionsParsed.load());
        CLogger::Log("Signatures saved to {}", out.c_str());
    }

private:

    enum class eFileTypes : std::uint8_t
    {
        UNK_FILE_TYPE = 0,
        
        LIB_FILE_TYPE,
        
        MAX_FILE_TYPE
    };

    static inline std::unordered_map<eFileTypes, std::string> strTypes = { {eFileTypes::UNK_FILE_TYPE, "UNKNOWN FILE TYPE"}, {eFileTypes::LIB_FILE_TYPE, "LIB FILE TYPE"} };
    
    static auto IsLibFile(std::ifstream& file) -> bool
    {
        constexpr std::string_view LIB_SIGNATURE = IMAGE_ARCHIVE_START;
        
        std::array<char, IMAGE_ARCHIVE_START_SIZE> buffer;
        
        file.read(buffer.data(), buffer.size());
        file.clear();
        file.seekg(0, std::ios::beg);

        return std::memcmp(buffer.data(), LIB_SIGNATURE.data(), buffer.size()) == 0;
    }
    
    static auto GetFileType(std::ifstream& file) -> eFileTypes
    {
        if (IsLibFile(file))
        {
            return eFileTypes::LIB_FILE_TYPE;
        }
        
        return eFileTypes::UNK_FILE_TYPE;
    }

    static auto GetFileTypeAsStr(const eFileTypes type) -> const std::string&
    {
        return strTypes.at(type);
    }

#pragma pack(push, 1)
    struct ArchiveMemberHeader
    {
        char Name[16];
        char Date[12];
        char UID[6];
        char GID[6];
        char Mode[8];
        char Size[10];
        char EOH[2];
    };
#pragma pack(pop)
    
    static constexpr auto ARCHIVE_MEMBER_HEADER_SIZE = sizeof(ArchiveMemberHeader);
    static_assert(ARCHIVE_MEMBER_HEADER_SIZE == 60, "ArchiveMemberHeader size must be 60.");
};