
#include <iostream>
#include "args.hxx"
#include <set>
#include <fstream>
#include <chrono>
#include "spdlog/spdlog.h"
#include "spdlog/fmt/fmt.h"
#include "spdlog/fmt/ostr.h"
#include <filesystem>
#include "Crc32.h"

extern "C" {
#include "zlib.h"
}
static const char signature[] = { 'P', 'A', 'C', 'K' };


//*Header
//    * (4 bytes)  signature = 'PACK'
//    * (4 bytes)  version
//    * (4 bytes)  index secret
//    * (4 bytes)  data secret
//    * (8 bytes)  index offset
//    * (4 bytes)  data crc32
static const int header_length = 28;

enum CompressionType : uint8_t
{
    None,
    Gzip
};

struct IndexItem
{
    std::string path;
    std::string fullpath;
    uint32_t offset;
    uint32_t length;
    CompressionType compressionType;
};

struct Context
{
    uint32_t version;
    uint32_t indexSecret;
    uint32_t dataSecret;
    std::vector<IndexItem> items;
    std::string pakfile;
};

void writeUint32InBigEndian(void* memory, uint32_t value)
{
    uint8_t* p = (uint8_t*)memory;
    p[0] = (uint8_t)(value >> 24);
    p[1] = (uint8_t)(value >> 16);
    p[2] = (uint8_t)(value >> 8);
    p[3] = (uint8_t)(value);
}

uint32_t readUint32InBigEndian(void* memory)
{
    uint8_t* p = (uint8_t*)memory;
    return (((uint32_t)p[0]) << 24) |
        (((uint32_t)p[1]) << 16) |
        (((uint32_t)p[2]) << 8) |
        (((uint32_t)p[3]));
}

void writeUint16InBigEndian(void* memory, uint16_t value)
{
    uint8_t* p = (uint8_t*)memory;
    p[0] = (uint8_t)(value >> 8);
    p[1] = (uint8_t)(value);
}

uint16_t readUint16InBigEndian(void* memory)
{
    uint8_t* p = (uint8_t*)memory;
    return (((uint16_t)p[0]) << 8) |
        (((uint16_t)p[1]));
}

void writeUint64InBigEndian(void* memory, uint64_t value)
{
    uint8_t* p = (uint8_t*)memory;
    p[0] = (uint8_t)(value >> 56);
    p[1] = (uint8_t)(value >> 48);
    p[2] = (uint8_t)(value >> 40);
    p[3] = (uint8_t)(value >> 32);
    p[4] = (uint8_t)(value >> 24);
    p[5] = (uint8_t)(value >> 16);
    p[6] = (uint8_t)(value >> 8);
    p[7] = (uint8_t)(value);
}

uint64_t readUint64InBigEndian(void* memory)
{
    uint8_t* p = (uint8_t*)memory;
    return (((uint64_t)p[0]) << 56) |
        (((uint64_t)p[1]) << 48) |
        (((uint64_t)p[2]) << 40) |
        (((uint64_t)p[3]) << 32) |
        (((uint64_t)p[4]) << 24) |
        (((uint64_t)p[5]) << 16) |
        (((uint64_t)p[6]) << 8) |
        (((uint64_t)p[7]));
}

inline void XorContent(uint64_t s, char* buf, size_t len) 
{
    if (s == 0)
        return;
    auto p = (char*)&s;
    auto left = len % sizeof(s);
    size_t i = 0;
    for (; i < len - left; i += sizeof(s)) {
        *(uint64_t*)&buf[i] ^= s;
    }
    for (auto j = i; i < len; ++i) {
        buf[i] ^= p[i - j];
    }
}


#define CHUNK 16384

/* Compress from file source to file dest until EOF on source.
  def() returns Z_OK on success, Z_MEM_ERROR if memory could not be
  allocated for processing, Z_STREAM_ERROR if an invalid compression
  level is supplied, Z_VERSION_ERROR if the version of zlib.h and the
  version of the library linked do not match, or Z_ERRNO if there is
  an error reading or writing the files. */
static int CompressString(const char* in_str, size_t in_len, std::string& out_str, int level)
{
    out_str.clear();

    if (!in_str)
        return Z_DATA_ERROR;

    int ret, flush;
    unsigned have;
    z_stream strm;

    unsigned char out[CHUNK];

    /* allocate deflate state */
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    ret = deflateInit2(&strm, level, Z_DEFLATED, MAX_WBITS + 16, MAX_MEM_LEVEL, Z_DEFAULT_STRATEGY);
    if (ret != Z_OK)
        return ret;

    std::shared_ptr<z_stream> sp_strm(&strm, [](z_stream* strm) {
        (void)deflateEnd(strm);
        });
    const char* end = in_str + in_len;

    size_t pos_index = 0;
    size_t distance = 0;
    /* compress until end of file */
    do {
        distance = end - in_str;
        strm.avail_in = (distance >= CHUNK) ? CHUNK : distance;
        strm.next_in = (Bytef*)in_str;

        // next pos
        in_str += strm.avail_in;
        flush = (in_str == end) ? Z_FINISH : Z_NO_FLUSH;

        /* run deflate() on input until output buffer not full, finish
          compression if all of source has been read in */
        do {
            strm.avail_out = CHUNK;
            strm.next_out = out;
            ret = deflate(&strm, flush);  /* no bad return value */
            if (ret == Z_STREAM_ERROR)
                break;
            have = CHUNK - strm.avail_out;
            out_str.append((const char*)out, have);
        } while (strm.avail_out == 0);
        if (strm.avail_in != 0)   /* all input will be used */
            break;

        /* done when last data in file processed */
    } while (flush != Z_FINISH);
    if (ret != Z_STREAM_END) /* stream will be complete */
        return Z_STREAM_ERROR;

    /* clean up and return */
    return Z_OK;
}

/* Decompress from file source to file dest until stream ends or EOF.
  inf() returns Z_OK on success, Z_MEM_ERROR if memory could not be
  allocated for processing, Z_DATA_ERROR if the deflate data is
  invalid or incomplete, Z_VERSION_ERROR if the version of zlib.h and
  the version of the library linked do not match, or Z_ERRNO if there
  is an error reading or writing the files. */
static int DecompressString(const char* in_str, size_t in_len, std::string& out_str)
{
    out_str.clear();

    if (!in_str)
        return Z_DATA_ERROR;

    int ret;
    unsigned have;
    z_stream strm;
    unsigned char out[CHUNK];

    /* allocate inflate state */
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = 0;
    strm.next_in = Z_NULL;
    ret = inflateInit2(&strm, MAX_WBITS + 16);
    if (ret != Z_OK)
        return ret;

    std::shared_ptr<z_stream> sp_strm(&strm, [](z_stream* strm) {
        (void)inflateEnd(strm);
        });

    const char* end = in_str + in_len;

    size_t pos_index = 0;
    size_t distance = 0;

    int flush = 0;
    /* decompress until deflate stream ends or end of file */
    do {
        distance = end - in_str;
        strm.avail_in = (distance >= CHUNK) ? CHUNK : distance;
        strm.next_in = (Bytef*)in_str;

        // next pos
        in_str += strm.avail_in;
        flush = (in_str == end) ? Z_FINISH : Z_NO_FLUSH;

        /* run inflate() on input until output buffer not full */
        do {
            strm.avail_out = CHUNK;
            strm.next_out = out;
            ret = inflate(&strm, Z_NO_FLUSH);
            if (ret == Z_STREAM_ERROR) /* state not clobbered */
                break;
            switch (ret) {
            case Z_NEED_DICT:
                ret = Z_DATA_ERROR;   /* and fall through */
            case Z_DATA_ERROR:
            case Z_MEM_ERROR:
                return ret;
            }
            have = CHUNK - strm.avail_out;
            out_str.append((const char*)out, have);
        } while (strm.avail_out == 0);

        /* done when inflate() says it's done */
    } while (flush != Z_FINISH);

    /* clean up and return */
    return ret == Z_STREAM_END ? Z_OK : Z_DATA_ERROR;
}

#undef CHUNK

int DoUnpack(const std::string& pakfile, std::string outDir)
{
    while (!outDir.empty() && (outDir.back() == '/' || outDir.back() == '\\'))
    {
        outDir.pop_back();
    }
    outDir.push_back('/');


    if (!std::filesystem::exists(outDir))
    {
        if (!std::filesystem::is_directory(outDir))
            std::filesystem::create_directories(outDir);
    }

    if (!std::filesystem::exists(outDir))
    {
        spdlog::error("The output directory does not exist: \"{0}\"", outDir);
        return -1;
    }

    std::ifstream inputFile(pakfile, std::ifstream::binary);
    if (!inputFile)
    {
        spdlog::error("Unable to open file: \"{0}\"", pakfile);
        return -1;
    }
    // 文件大小
    inputFile.seekg(0, inputFile.end);
    auto&& fileSize = inputFile.tellg();
    
    // 头部信息读取
    char headBuffer[header_length];
    inputFile.seekg(0, inputFile.beg);
    inputFile.read(headBuffer, sizeof(headBuffer));
    if (!inputFile)
    {
        spdlog::error("File \"{0}\" read failed", pakfile);
        return -1;
    }

    // 头部信息校验
    if (fileSize < header_length || memcmp(headBuffer, signature, sizeof(signature)) != 0)
    {
        spdlog::error("Not a pack file");
        return -1;
    }

    uint64_t offset = sizeof(signature);

    // version
    auto version = readUint32InBigEndian(&headBuffer[offset]);
    offset += 4;

    // 索引加密秘钥
    auto indexSecret = readUint32InBigEndian(&headBuffer[offset]);
    offset += 4;

    // 数据加密秘钥
    auto dataSecret = readUint32InBigEndian(&headBuffer[offset]);
    offset += 4;

    // 索引偏移
    auto indexOffset = readUint64InBigEndian(&headBuffer[offset]);
    offset += 8;

    // crc32校验码
    auto fileCrc32Value = readUint32InBigEndian(&headBuffer[offset]);
    offset += 4;

    if (version != 0)
    {
        spdlog::error("Unsupported version {0}", version);
        return false;
    }
    
    // 重置偏移值
    offset = indexOffset;
    uint64_t length = fileSize;

    // 索引下标越界
    if (length < indexOffset)
    {
        spdlog::error("Not a pack file");
        return -1;
    }

    // 空文件
    if (length == indexOffset)
    {
        spdlog::error("Empty File"); 
        return 0;
    }

    // 分配索引区域内存
    auto indexBufLength = length - indexOffset;
    std::unique_ptr<char[]> indexBuffer(new char[indexBufLength]);
    if (!indexBuffer)
    {
        spdlog::error("out of memory");
        return -1;
    }

    // 读取索引数据
    inputFile.seekg(indexOffset, inputFile.beg);
    inputFile.read(&indexBuffer[0], indexBufLength);
    if (!inputFile)
    {
        spdlog::error("File \"{0}\" read index data failed", pakfile);
        return -1;
    }

#define CHECK_SIZE(num) if(offset + num > indexBufLength) { spdlog::error("Not a pack file"); return -1; }

    // 数据缓存
    std::string dataBuffer;
    std::string plaintext;
    uint32_t sumCrc32Value = 0;
    offset = 0;
    while(offset < indexBufLength)
    {
        CHECK_SIZE(8);
        auto itemOffset = readUint64InBigEndian(&indexBuffer[offset]);
        offset += 8;

        CHECK_SIZE(4);
        auto itemLength = readUint32InBigEndian(&indexBuffer[offset]);
        offset += 4;

        CHECK_SIZE(1);
        auto nameLength = (uint8_t)indexBuffer[offset];
        offset += 1;

        CHECK_SIZE(1);
        CompressionType compressionType = (CompressionType)(indexBuffer[offset]);
        offset += 1;

        CHECK_SIZE(nameLength);
        auto itemPath = std::string(&indexBuffer[offset], nameLength);
        offset += nameLength;
        
        XorContent(indexSecret, itemPath.data(), itemPath.length());
        std::filesystem::path itemFullpath = outDir + itemPath;

        // 预分配内存
        dataBuffer.reserve(itemLength);
        if (dataBuffer.capacity() < itemLength)
        {
            spdlog::error("out of memory, expected size: {}", itemLength);
            return -1;
        }
        // 读取文件数据
        inputFile.seekg(itemOffset, inputFile.beg);
        inputFile.read(&dataBuffer[0], itemLength);
        if (!inputFile)
        {
            spdlog::error("Failed to read data from file: '{0}'", itemPath);
            return -1;
        }

        // 创建对应的目录结构
        if(!std::filesystem::is_directory(itemFullpath.parent_path()))
            std::filesystem::create_directories(itemFullpath.parent_path());

        std::ofstream ofs(itemFullpath, std::ios_base::trunc | std::ios_base::binary);
        if (!ofs)
        {
            spdlog::error("Unable to open file: \"{0}\"", itemFullpath.string());
            return -1;
        }

        sumCrc32Value = crc32_fast(dataBuffer.data(), itemLength, sumCrc32Value);
        XorContent(dataSecret, dataBuffer.data(), itemLength);

        switch (compressionType)
        {
        case None:
        {
            ofs.write(dataBuffer.data(), itemLength);
        }
            break;
        case Gzip:
        {
            if (DecompressString(dataBuffer.data(), itemLength, plaintext) == Z_OK)
            {
                ofs.write(plaintext.data(), plaintext.length());
            }
            else
            {
                spdlog::error("File '{0}' decompression failed", itemPath);
            }
        }
            break;
        default:
            spdlog::error("Unsupported compression method: {0}", compressionType);
            break;
        }
        ofs.close();

    }
    assert(offset == indexBufLength);
#undef CHECK_SIZE

    if (fileCrc32Value != sumCrc32Value)
    {
        spdlog::error("CRC verification inconsistency");
        spdlog::error("file crc32: 0x{:X}, current crc32: 0x{:X}", fileCrc32Value, sumCrc32Value);
    }

    return 0;
}

int DoPack(Context& context, const std::set<std::string>& compressFileExtSet)
{
    std::ofstream ofs(context.pakfile, std::ios_base::trunc | std::ios_base::binary);
    if (!ofs)
    {
        spdlog::error("Unable to open file: \"{0}\"", context.pakfile);
        return -1;
    }

    uint64_t offset = 0;
    char header[header_length] = { 0 };
    ofs.write(header, sizeof(header));

    offset = sizeof(header);
    std::string buffer;
    std::string compressedStr;

    uint32_t crc32Value = 0;
    for (auto& item : context.items)
    {
        std::ifstream f(item.fullpath, std::ifstream::binary);
        if (!f)
        {
            spdlog::error("Unable to open file: \"{0}\"", item.fullpath);
            return -1;
        }
        f.seekg(0, f.end);
        auto&& length = f.tellg();
        if ((uint64_t)length > std::numeric_limits<int32_t>::max())
        {
            f.close();
            spdlog::error("File \"{0}\" is too large", item.fullpath);
            return -1;
        }
        f.seekg(0, f.beg);

        buffer.reserve(length);
        f.read(buffer.data(), length);
        if (!f)
        {
            spdlog::error("File \"{0}\" read failed", item.fullpath);
            return -1;
        }
        f.close();

        if (compressFileExtSet.count(std::filesystem::path(item.path).extension().string()) > 0)
        {
            if (CompressString(buffer.data(), length, compressedStr, Z_BEST_SPEED) == Z_OK)
            {
                length = compressedStr.length();
                item.compressionType = CompressionType::Gzip;
                XorContent(context.dataSecret, compressedStr.data(), compressedStr.length());
                ofs.write(compressedStr.data(), compressedStr.length());
                crc32Value = crc32_fast(compressedStr.data(), compressedStr.length(), crc32Value);
            }
            else
            {
                spdlog::error("File \"{0}\" compression failed", item.fullpath);
            }
        }

        if (item.compressionType == CompressionType::None)
        {
            XorContent(context.dataSecret, buffer.data(), length);
            ofs.write(buffer.data(), length);
            crc32Value = crc32_fast(buffer.data(), length, crc32Value);
        }

        item.offset = offset;
        item.length = length;
        offset += length;
    }

    uint8_t fileInfoBuf[8 + 4 + 1 + 1];
    for (auto& item : context.items)
    {
        writeUint64InBigEndian(fileInfoBuf, item.offset);
        writeUint32InBigEndian(fileInfoBuf + 8, item.length);
        fileInfoBuf[12] = (uint8_t)item.path.length();
        fileInfoBuf[13] = item.compressionType;

        ofs.write((char*)fileInfoBuf, sizeof(fileInfoBuf));
        XorContent(context.indexSecret, item.path.data(), item.path.length());
        ofs.write(item.path.data(), item.path.length());
    }

    {
        auto indexOffset = offset;

        offset = 0;
        memcpy(header, signature, sizeof(signature));
        offset += 4;

        // version
        writeUint32InBigEndian(header + offset, context.version);
        offset += 4;

        // index secret
        writeUint32InBigEndian(header + offset, context.indexSecret);
        offset += 4;

        // data secret
        writeUint32InBigEndian(header + offset, context.dataSecret);
        offset += 4;

        // index offset
        writeUint64InBigEndian(header + offset, indexOffset);
        offset += 8;

        // crc32
        writeUint32InBigEndian(header + offset, crc32Value);
        offset += 4;

        ofs.seekp(0, std::ios_base::beg);
        ofs.write(header, sizeof(header));
    }
    ofs.close();

     return 0;
}


args::ArgumentParser globalParser("packtool");

args::Group arguments("arguments");
args::HelpFlag h(arguments, "help", "help", { 'h', "help" });
args::ValueFlag<int> logLevel(arguments, "0-6", "The log level", { "log_level" });

void ReadGlobalArguments()
{
    if (logLevel && logLevel.Get() >= 0 && logLevel.Get() < spdlog::level::level_enum::n_levels)
    {
        spdlog::set_level((spdlog::level::level_enum)logLevel.Get());
    }
}

void UnpackCommand(args::Subparser& parser)
{
    args::ValueFlag<std::string> inputfile(parser, "file path", "The .PACK file path", { 'i' });
    args::ValueFlag<std::string> output(parser, "file path", "The output directory", { 'o' });
    parser.Parse();

    ReadGlobalArguments();

    if (output.Get().empty() || inputfile.Get().empty())
    {
        std::cout << globalParser << std::endl;
        return;
    }

    try
    {
        auto start = std::chrono::high_resolution_clock::now();
        auto code = DoUnpack(inputfile.Get(), output.Get());
        std::chrono::duration<double, std::milli> elapsed = std::chrono::high_resolution_clock::now() - start;
        spdlog::info("unpack time: {0}ms", elapsed.count());

        ::exit(code);
    }
    catch (const std::exception& e)
    {
        spdlog::error("unpack error: {0}", e.what());
        ::exit(-1);
    }
}

void PackCommand(args::Subparser& parser)
{
    args::NargsValueFlag<std::string> srcDirs(parser, "path...", "The source directory", { 's', "src" }, args::Nargs(1, INT_MAX));
    args::NargsValueFlag<std::string> compressFileExt(parser, "ext...", "The file types that need to be compressed", {'c', "compress_file_ext"}, args::Nargs(1, INT_MAX));
    args::ValueFlag<uint32_t> indexSecret(parser, "uint32", "The index secret", { 'i', "isecret" });
    args::ValueFlag<uint32_t> dataSecret(parser, "uint32", "The data secret", { 'd', "dsecret" });
    args::ValueFlag<uint32_t> useParentDirectory(parser, "0/1", "The data secret", { "keep_parent_directory" });
    args::ValueFlag<std::string> output(parser, "file path", "The output file path", { 'o' });
    args::ValueFlag<uint64_t> maximum(parser, "MB", "The maximum size of a single file", { "maximum"});
    parser.Parse();

    ReadGlobalArguments();

    if (srcDirs.Get().empty() || output.Get().empty())
    {
        std::cout << globalParser << std::endl;
        return;
    }

    std::vector<std::shared_ptr<Context>> contexts;

    std::shared_ptr<Context> pContext = NULL;

    IndexItem item;
    uint64_t curBytes = 0ULL;
    uint64_t maxBytes = maximum.Get() * 1024 * 1024;
    int32_t chunkCount = 0;
    for (auto&& path : srcDirs.Get())
    {
        auto src = std::filesystem::absolute(path);
        std::string basePath = src.string();

        while (!basePath.empty() && (basePath.back() == '/' || basePath.back() == '\\'))
        {
            basePath.pop_back();
        }

        if (useParentDirectory.Get() == 1)
        {
            while (!basePath.empty() && (basePath.back() != '/' && basePath.back() != '\\'))
            {
                basePath.pop_back();
            }
        }

        while (!basePath.empty() && (basePath.back() == '/' || basePath.back() == '\\'))
        {
            basePath.pop_back();
        }
        basePath.push_back('/');

        for (auto&& o : std::filesystem::recursive_directory_iterator(src)) 
        {
            auto&& p = o.path();
            // 不是文件, 没有文件名, 0字节 就跳过
            if (!o.is_regular_file() || !p.has_filename()) continue;

            auto path = p.string().substr(basePath.size());
            for (auto& c : path) if (c == '\\') c = '/';

            item.path = path;
            item.fullpath = p.string();
            item.compressionType = CompressionType::None;
            item.offset = 0;
            item.length = 0;

            if (pContext == NULL)
            {
                pContext = std::make_shared<Context>();
                pContext->version = 0;
                pContext->indexSecret = indexSecret.Get();
                pContext->dataSecret = dataSecret.Get();
                pContext->pakfile = output.Get();
                contexts.push_back(pContext);
            }
            pContext->items.push_back(item);

            curBytes += std::filesystem::file_size(p);

            if (maxBytes > 0 && curBytes >= maxBytes)
            {
                curBytes = 0;
                pContext = NULL;
            }
        }
    }
    
    std::set<std::string> compressFileExtSet;
    for (auto&& ext : compressFileExt.Get())
        compressFileExtSet.insert(ext);

    try
    {
        if (contexts.size() > 1)
        {
            for (std::size_t i = 0; i < contexts.size(); ++i)
            {
                auto ext = std::filesystem::path(contexts[i]->pakfile).extension();
                auto prefix = contexts[i]->pakfile.substr(0, contexts[i]->pakfile.size() - ext.string().size());
                contexts[i]->pakfile = prefix + std::to_string(i) + ext.string();
            }
        }

        auto start = std::chrono::high_resolution_clock::now();
        int code = 0;
        for (auto context : contexts)
        {
            code = DoPack(*context, compressFileExtSet);
            if (code < 0)
            {
                if (std::filesystem::exists(context->pakfile))
                    std::filesystem::remove(context->pakfile);
                break;
            }
        }
        std::chrono::duration<double, std::milli> elapsed = std::chrono::high_resolution_clock::now() - start;
        spdlog::info("pack time: {0}ms", elapsed.count());

        ::exit(code == 0 ? contexts.size() : code);
    }
    catch (const std::exception& e)
    {
        spdlog::error("pack error: {0}", e.what());
        ::exit(-1);
    }
}

int main(int argc, char** argv)
{
    args::Group commands(globalParser, "commands");
    args::Command pack(commands, "pack", "create PAK", &PackCommand);
    args::Command unpack(commands, "unpack", "unpack PAK file", &UnpackCommand);
    
    args::GlobalOptions globals(globalParser, arguments);

    try
    {
        globalParser.ParseCLI(argc, argv);
    }
    catch (args::Help)
    {
        std::cout << globalParser << std::endl;
    }
    catch (args::Error& e)
    {
        spdlog::error("{0}", e.what());
        //spdlog::error("{0}\n{1}", e.what(), fmt::streamed(p));
        std::cout << globalParser << std::endl;
        return -1;
    }
    return -1;
}

