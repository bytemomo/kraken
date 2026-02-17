#include <algorithm>
#include <csignal>
#include <cstring>
#include <numeric>

#include "kickcat/ESC/EmulatedESC.h"
#include "kickcat/Frame.h"
#include "kickcat/slave/Slave.h"

#include "kickcat/CoE/EsiParser.h"
#include "kickcat/CoE/mailbox/response.h"

#ifdef __linux__
#include "kickcat/OS/Linux/Socket.h"
#elif __MINGW64__
#include "kickcat/OS/Windows/Socket.h"
#else
#error "Unsupported platform"
#endif


using namespace kickcat;
using namespace kickcat::slave;

static volatile bool running = true;

static void signal_handler(int)
{
    running = false;
}

int main(int argc, char* argv[])
{
    if (argc < 3)
    {
        printf("Usage: ./network_simulator interface_name eeprom_s1.bin ... eeprom_sn.bin");
        return -1;
    }

    size_t slaveCount = argc - 2;
    std::vector<EmulatedESC> escs;
    std::vector<PDO> pdos;
    std::vector<Slave> slaves;
    std::vector<uint8_t*> inputPdo;
    std::vector<uint8_t*> outputPdo;

    escs.reserve(slaveCount);
    pdos.reserve(slaveCount);
    slaves.reserve(slaveCount);
    inputPdo.reserve(slaveCount);
    outputPdo.reserve(slaveCount);
    for (int i = 2; i < argc; ++i)
    {
        escs.emplace_back(argv[i]);
        pdos.emplace_back(&escs.back());
        slaves.emplace_back(&escs.back(), &pdos.back());

        inputPdo.push_back(new uint8_t[1024]);
        outputPdo.push_back(new uint8_t[1024]);
        pdos.back().setInput(inputPdo.back());
        pdos.back().setOutput(outputPdo.back());
    }

    CoE::EsiParser parser;
    auto coe_dict = parser.loadFile("foot.xml");

    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    printf("Start EtherCAT network simulator on %s with %ld slaves\n", argv[1], escs.size());
    fflush(stdout);
    auto socket = std::make_shared<Socket>();
    socket->open(argv[1]);
    socket->setTimeout(100ms);  // Short timeout to allow signal handling

    std::vector<nanoseconds> stats;
    stats.reserve(1000);

    auto& esc0   = escs.at(0);
    auto& slave0 = slaves.at(0);
    mailbox::response::Mailbox mbx(&esc0, 1024);
    mbx.enableCoE(std::move(coe_dict));
    slave0.setMailbox(&mbx);


    for (auto& slave : slaves)
    {
        slave.start();
    }


    while (running)
    {
        Frame frame;
        int32_t r = socket->read(frame.data(), ETH_MAX_SIZE);
        if (r < 0)
        {
            // Timeout or signal - just continue and check running flag
            continue;
        }
        if (r == 0)
        {
            continue;
        }

        auto t1 = since_epoch();
        while (true)
        {
            auto [header, data, wkc] = frame.peekDatagram();
            if (header == nullptr)
            {
                break;
            }

            for (auto& esc : escs)
            {
                //auto raw = t1.count();
                //esc.write(0x1800, &raw, sizeof(decltype(raw)));
                esc.processDatagram(header, data, wkc);
            }

            for (auto& slave : slaves)
            {
                slave.routine();
                if (slave.state() == State::SAFE_OP)
                {
                    slave.validateOutputData();
                }
            }
        }

        // Swap source and destination MAC for response
        uint8_t* eth = frame.data();
        uint8_t tmp[6];
        memcpy(tmp, eth, 6);           // save dst
        memcpy(eth, eth + 6, 6);       // dst = src
        memcpy(eth + 6, tmp, 6);       // src = old dst

        int32_t written = socket->write(frame.data(), r);
        if (written < 0)
        {
            printf("Write back frame: something wrong happened. Aborting...\n");
            return -2;
        }
        if (written != r)
        {
            printf("Partial write: sent %d of %d bytes\n", written, r);
        }
        auto t2 = since_epoch();

        stats.push_back(t2 - t1);
        if (stats.size() >= 1000)
        {
            std::sort(stats.begin(), stats.end());

            printf("[%f] frame processing time: \n\t min: %f\n\t max: %f\n\t avg: %f\n", seconds_f(since_start()).count(),
                stats.front().count() / 1000.0,
                stats.back().count()  / 1000.0,
                (std::reduce(stats.begin(), stats.end()) / stats.size()).count() / 1000.0);
            stats.clear();
        }

    }

    printf("\nShutting down simulator...\n");
    socket->close();
    return 0;
}
