#include "KernelContext.hpp"
#include "sys/sysproto.hpp"
#include "thread/Process.hpp"
#include "thread/Thread.hpp"
#include "time.hpp"
#include "utils/Logs.hpp"

namespace orbis {
SysResult kern_sysctl(Thread *thread, ptr<sint> name, uint namelen,
                      ptr<void> old, ptr<size_t> oldlenp, ptr<void> new_,
                      size_t newlen) {
  enum sysctl_ctl { unspec, kern, vm, vfs, net, debug, hw, machdep, user, dev };

  enum sysctl_kern {
    proc = 14,
    boottime = 21,
    os_rel_date = 24,
    usrstack = 33,
    arnd = 37,

    // FIXME
    smp_cpus = 1000,
    sdk_version,
    sched_cpusetsize,
    proc_ptc,
    cpu_mode,
    rng_pseudo,
    backup_restore_mode,
    console,
    init_safe_mode,
    geom,
  };

  enum sysctl_hw {
    ncpu = 3,
    pagesize = 7,

    // FIXME
    config = 1000,
    sce_main_socid,
  };

  enum sysctl_vm {
    // FIXME
    swap_avail = 1000,
    swap_total,
    kern_heap_size,
    budgets,
  };

  enum sysctl_hw_config {
    chassis_info,
    optical_out = 1000,
  };

  enum sysctl_machdep {
    // FIXME
    tsc_freq = 1000,
    liverpool,
    bootparams,
    idps,
    openpsid_for_sys,
    sceKernelIsCavern,
    use_idle_hlt,
  };

  enum sysctl_machdep_liverpool {
    telemetry = 1000,
    icc_max,
  };
  enum sysctl_machdep_bootparams {
    is_main_on_standby = 1000,
  };

  enum sysctl_kern_geom {
    updtfmt = 1000,
  };

  enum sysctl_vm_budgets_ {
    mlock_total = 1000,
    mlock_avail = 1000,
  };

  enum sysctl_dev {
    cpu = 1000,
  };

  enum sysctl_dev_cpu {
    freq = 1000,
  };

  struct ProcInfo {
    char data[0x448];
  };

  // Safely read name array from guest memory
  // name is ptr<sint> pointing to an array, so name[i] is ptr<sint> to the i-th element
  std::vector<sint> safeNames(namelen);
  for (unsigned int i = 0; i < namelen; ++i) {
    if (auto result = uread(safeNames[i], name + i); result != ErrorCode{}) {
      return result;  // Failed to read name array
    }
  }
  // Use safeNames instead of name[] from here on
  #define name safeNames

  // Safely read oldlenp value at start for initial validation
  // NOTE: Handlers that need to re-read oldlenp should use uread(oldlen, oldlenp)
  // For simple safeOldLen dereferences, use safeOldLen below
  size_t safeOldLen = 0;
  if (oldlenp != nullptr) {
    if (auto result = uread(safeOldLen, oldlenp); result != ErrorCode{}) {
      return result;  // Failed to read oldlenp
    }
  }

  // for (unsigned int i = 0; i < namelen; ++i) {
  //   std::fprintf(stderr, "   name[%u] = %d\n", i, name[i]);
  // }

  if (namelen == 6) {
    // 4.17.0.0.3.0
    if (name[0] == net && name[1] == 17 && name[2] == 0 && name[3] == 0 &&
        name[4] == 3 && name[5] == 0) {
      if (g_context->fwSdkVersion == 0) {
        // proto fw
        return {};
      }

      return ErrorCode::OPNOTSUPP;
    }
  }

  if (namelen == 3) {
    // 1 - 14 - 41 - debug flags?

    if (name[0] == machdep && name[1] == bootparams &&
        name[2] == is_main_on_standby) {
      if (safeOldLen != 4 || new_ != nullptr || newlen != 0) {
        return ErrorCode::INVAL;
      }

      *(uint32_t *)old = 0;
      return {};
    }

    if (name[0] == machdep && name[1] == use_idle_hlt) {
      if (safeOldLen != 4 || new_ != nullptr || newlen != 0) {
        return ErrorCode::INVAL;
      }

      // Return 1 to enable idle halt (power saving)
      *(uint32_t *)old = 1;
      return {};
    }

    if (name[0] == kern && name[1] == os_rel_date) {
      if (safeOldLen != 4 || new_ != nullptr || newlen != 0) {
        return ErrorCode::INVAL;
      }

      *(uint32_t *)old = 0xaae93; // FIXME
      return {};
    }

    if (name[0] == kern && name[1] == proc && name[2] == 41) {
      // std::printf("   kern.14.41\n");

      if (safeOldLen != 4 || new_ != nullptr || newlen != 0) {
        return ErrorCode::INVAL;
      }

      *(uint32_t *)old = 0;
      return {};
    }

    if (name[0] == kern && name[1] == proc && name[2] == 42) {
      // std::printf("   kern.14.42\n");

      if ((oldlenp != nullptr && safeOldLen != 0) || new_ == nullptr ||
          newlen != 4) {
        return ErrorCode::INVAL;
      }

      // set record
      auto record = *(uint32_t *)new_;
      // ORBIS_LOG_WARNING("sys___sysctl: set record", record);
      return {};
    }

    if (name[0] == kern && name[1] == proc && name[2] == 8) {
      // KERN_PROC_PROC
      ORBIS_LOG_ERROR("KERN_PROC_PROC");
      thread->where();
      std::memset(old, 0, sizeof(ProcInfo));
      return uwrite(oldlenp, sizeof(ProcInfo));
    }

    if (name[0] == machdep && name[1] == liverpool && name[2] == telemetry) {
      if (safeOldLen != 8 || new_ != nullptr || newlen != 0) {
        return ErrorCode::INVAL;
      }

      *(uint64_t *)old = 0;
      return {};
    }
    if (name[0] == machdep && name[1] == liverpool && name[2] == icc_max) {
      if (safeOldLen != 4 || new_ != nullptr || newlen != 0) {
        return ErrorCode::INVAL;
      }

      *(uint32_t *)old = 0;
      return {};
    }

    if (name[0] == hw && name[1] == config && name[2] == chassis_info) {
      if (safeOldLen != 8 || new_ != nullptr || newlen != 0) {
        return ErrorCode::INVAL;
      }

      *(uint64_t *)old = 0;
      return {};
    }

    if (name[0] == kern && name[1] == geom && name[2] == updtfmt) {
      if (safeOldLen != 4 || new_ != nullptr || newlen != 0) {
        return ErrorCode::INVAL;
      }

      *(uint32_t *)old = 0;
      return {};
    }

    if (name[0] == vm && name[1] == budgets && name[2] == mlock_total) {
      if (safeOldLen != 8 || new_ != nullptr || newlen != 0) {
        return ErrorCode::INVAL;
      }

      auto budget = g_context->budgets.get(thread->tproc->budgetId);
      auto fmem = budget->get(BudgetResource::Fmem);
      *(uint64_t *)old = fmem.total;
      return {};
    }

    if (name[0] == vm && name[1] == budgets && name[2] == mlock_avail) {
      if ((safeOldLen != 16 && safeOldLen != 8) || new_ != nullptr || newlen != 0) {
        return ErrorCode::INVAL;
      }

      auto budget = g_context->budgets.get(thread->tproc->budgetId);
      auto fmem = budget->get(BudgetResource::Fmem);

      auto result = (uint64_t *)old;
      result[0] = fmem.total - fmem.used;
      if (safeOldLen == 16) {
        result[1] = fmem.total;
      }
      return {};
    }
  }

  if (namelen >= 3) {
    if (name[0] == kern && name[1] == proc && name[2] == 1) {
      ORBIS_LOG_ERROR("KERN_PROC_PROC 2");

      if (namelen >= 4) {
        auto process = findProcessById(name[3]);
        if (process == nullptr || process->exitStatus.has_value()) {
          return ErrorCode::SRCH;
        }
      }

      std::memset(old, 0, sizeof(ProcInfo));
      return uwrite(oldlenp, sizeof(ProcInfo));
    }
  }

  if (namelen == 4) {
    if (name[0] == dev && name[1] == cpu && name[3] == freq) {
      // dev.cpu.N.freq - CPU frequency in MHz
      // name[2] is the CPU index (0-7)
      if (safeOldLen != 4 || new_ != nullptr || newlen != 0) {
        return ErrorCode::INVAL;
      }
      // PS4 CPU (AMD Jaguar) base frequency is 1.6 GHz = 1600 MHz
      *(uint32_t *)old = 1600;
      return {};
    }

    if (name[0] == kern && name[1] == proc && name[2] == 37) {
      if (oldlenp && old && safeOldLen == 4) {
        return uwrite(ptr<uint32_t>(old), ~0u);
      }
    }

    if (name[0] == kern && name[1] == proc && name[2] == 55) {
      if (g_context->fwType != FwType::Ps5) {
        return orbis::ErrorCode::INVAL;
      }

      if (oldlenp && old && safeOldLen == 4) {
        return uwrite<uint32_t>(ptr<uint32_t>(old),
                                thread->tproc->type == ProcessType::Ps5 ? 1
                                                                        : 0);
      }
    }

    if (name[0] == kern && name[1] == proc && name[2] == 36) {
      Process *process = thread->tproc;
      if (process->pid != name[3]) {
        process = findProcessById(name[3]);
        if (process == nullptr) {
          ORBIS_LOG_ERROR("get sdk version by pid: process not found", name[3],
                          thread->tproc->pid);
          return ErrorCode::SRCH;
        }
      }

      size_t oldlen;
      ORBIS_RET_ON_ERROR(uread(oldlen, oldlenp));

      if (oldlen < sizeof(uint32_t)) {
        return ErrorCode::INVAL;
      }

      auto sdkVersion = process->sdkVersion;
      if (sdkVersion == 0) {
        sdkVersion = g_context->fwSdkVersion;
      }

      ORBIS_RET_ON_ERROR(uwrite(ptr<uint32_t>(old), sdkVersion));
      ORBIS_LOG_ERROR("get sdk version by pid", name[3], sdkVersion);
      return uwrite(oldlenp, sizeof(uint32_t));
    }

    if (name[0] == 1 && name[1] == proc && name[2] == 35) {
      // AppInfo get/set

      // 1 - 14 - 35 - pid
      Process *process = thread->tproc;
      if (process->pid != name[3] && name[3] != -1) {
        process = findProcessById(name[3]);
        if (process == nullptr) {
          ORBIS_LOG_ERROR("appinfo process not found", name[3],
                          thread->tproc->pid);
          return ErrorCode::SRCH;
        }
      }

      if (old) {
        size_t oldlen;
        ORBIS_RET_ON_ERROR(uread(oldlen, oldlenp));

        if (oldlen == sizeof(AppInfoEx)) {
          ORBIS_LOG_ERROR("get AppInfoEx", process->appInfo.appId,
                          process->appInfo.unk0, process->appInfo.unk1,
                          process->appInfo.appType, process->appInfo.titleId,
                          process->appInfo.unk2, process->appInfo.unk3,
                          process->appInfo.unk5, process->appInfo.unk6,
                          process->appInfo.unk7, process->appInfo.unk8);

          ORBIS_RET_ON_ERROR(uwrite((ptr<AppInfoEx>)old, process->appInfo));
          ORBIS_RET_ON_ERROR(uwrite(oldlenp, sizeof(AppInfoEx)));
        } else if (oldlen == sizeof(AppInfo)) {
          ORBIS_LOG_ERROR("get AppInfo", process->appInfo.appId,
                          process->appInfo.unk0, process->appInfo.unk1,
                          process->appInfo.appType, process->appInfo.titleId,
                          process->appInfo.unk2, process->appInfo.unk3,
                          process->appInfo.unk5, process->appInfo.unk6,
                          process->appInfo.unk7, process->appInfo.unk8);

          ORBIS_RET_ON_ERROR(
              uwrite((ptr<AppInfo>)old, (AppInfo &)process->appInfo));
          ORBIS_RET_ON_ERROR(uwrite(oldlenp, sizeof(AppInfo)));
        } else {
          return ErrorCode::INVAL;
        }
      }

      if (new_) {
        if (newlen == sizeof(AppInfoEx)) {
          auto result = uread(process->appInfo, (ptr<AppInfoEx>)new_);
          if (result == ErrorCode{}) {
            auto &appInfo = process->appInfo;
            ORBIS_LOG_ERROR("set AppInfoEx", appInfo.appId, appInfo.unk0,
                            appInfo.unk1, appInfo.appType, appInfo.titleId,
                            appInfo.unk2, appInfo.unk3, appInfo.unk5,
                            appInfo.unk6, appInfo.unk7, appInfo.unk8);

            // HACK
            if (appInfo.appId == 0 && appInfo.unk4 == 0) {
              appInfo.unk4 = orbis::slong(0x80000000'00000000);
            }
          }

          return result;
        } else if (newlen == sizeof(AppInfo)) {
          auto result = uread((AppInfo &)process->appInfo, (ptr<AppInfo>)new_);
          if (result == ErrorCode{}) {
            auto &appInfo = process->appInfo;
            ORBIS_LOG_ERROR("set AppInfo", appInfo.appId, appInfo.unk0,
                            appInfo.unk1, appInfo.appType, appInfo.titleId,
                            appInfo.unk2, appInfo.unk3, appInfo.unk5,
                            appInfo.unk6, appInfo.unk7, appInfo.unk8);

            // HACK
            if (appInfo.appId == 0 && appInfo.unk4 == 0) {
              appInfo.unk4 = orbis::slong(0x80000000'00000000);
            }
          }
        }
      }
      return {};
    }

    if (name[0] == 1 && name[1] == 14 && name[2] == 44) {
      // GetLibkernelTextLocation
      if (safeOldLen != 16) {
        return ErrorCode::INVAL;
      }

      auto *dest = (uint64_t *)old;

      for (auto [id, mod] : thread->tproc->modulesMap) {
        if (std::string_view("libkernel") == mod->moduleName) {
          dest[0] = (uint64_t)mod->segments[0].addr;
          dest[1] = mod->segments[0].size;
          return {};
        }
      }

      return ErrorCode::SRCH;
    }

    if (name[0] == kern && name[1] == proc && name[2] == 64) {
      auto appInfo = g_context->appInfos.get(name[3]);
      if (appInfo == nullptr) {
        return ErrorCode::SRCH; // ?
      }

      if (old) {
        size_t oldlen;
        ORBIS_RET_ON_ERROR(uread(oldlen, oldlenp));
        if (oldlen < sizeof(uint32_t)) {
          return ErrorCode::INVAL;
        }

        ORBIS_LOG_TODO("1.14.64 get", name[3], appInfo->appState);

        ORBIS_RET_ON_ERROR(uwrite(ptr<uint32_t>(old), 5u));
        ORBIS_RET_ON_ERROR(uwrite<size_t>(oldlenp, sizeof(uint32_t)));
      }

      if (new_) {
        if (newlen != sizeof(uint32_t)) {
          return ErrorCode::INVAL;
        }

        uint32_t appState;
        ORBIS_RET_ON_ERROR(uread(appState, ptr<uint32_t>(new_)));
        ORBIS_LOG_TODO("1.14.64 set", name[3], appState);
        appInfo->appState = appState;
      }
      return {};
    }

    if (name[0] == 1 && name[1] == proc && name[2] == 65) {
      // AppInfo by appId get/set
      // 1 - 14 - 65 - appId
      auto appInfo = g_context->appInfos.get(name[3]);
      if (appInfo == nullptr) {
        ORBIS_LOG_ERROR("appinfo appId not found", name[3], thread->tproc->pid);
        return ErrorCode::SRCH;
      }

      if (old) {
        size_t oldlen;
        ORBIS_RET_ON_ERROR(uread(oldlen, oldlenp));

        ORBIS_LOG_ERROR("1.14.65", name[3], oldlen);

        if (oldlen < sizeof(AppInfoEx)) {
          return ErrorCode::INVAL;
        }

        ORBIS_LOG_ERROR("get AppInfo2", appInfo->appId, appInfo->unk0,
                        appInfo->unk1, appInfo->appType, appInfo->titleId,
                        appInfo->unk2, appInfo->unk3, appInfo->unk5,
                        appInfo->unk6, appInfo->unk7, appInfo->unk8);

        if (auto errc = uwrite((ptr<AppInfoEx>)old,
                               *static_cast<AppInfoEx *>(appInfo.get()));
            errc != ErrorCode{}) {
          return errc;
        }

        if (auto errc = uwrite(oldlenp, sizeof(AppInfoEx));
            errc != ErrorCode{}) {
          return errc;
        }
      }

      if (new_) {
        return ErrorCode::INVAL;
      }

      return {};
    }

    if (name[0] == kern && name[1] == proc && name[2] == 68) {
      Process *process = thread->tproc;
      if (process->pid != name[3]) {
        process = findProcessById(name[3]);
        if (process == nullptr) {
          ORBIS_LOG_ERROR("get ps5 sdk version by pid: process not found",
                          name[3], thread->tproc->pid);
          return ErrorCode::SRCH;
        }
      }

      size_t oldlen;
      ORBIS_RET_ON_ERROR(uread(oldlen, oldlenp));

      if (oldlen < sizeof(uint32_t)) {
        return ErrorCode::INVAL;
      }

      auto sdkVersion = process->sdkVersion;
      if (sdkVersion == 0) {
        sdkVersion = g_context->fwSdkVersion;
      }

      ORBIS_RET_ON_ERROR(uwrite(ptr<uint32_t>(old), sdkVersion));
      ORBIS_LOG_ERROR("get ps5 sdk version by pid", name[3], sdkVersion);
      return uwrite(oldlenp, sizeof(uint32_t));
    }
  }

  if (namelen == 2) {
    switch (name[0]) {
    case sysctl_ctl::unspec: {
      switch (name[1]) {
      case 3: {
        // String lookup for sysctl by name - validate parameters
        if (new_ == nullptr || newlen == 0 || newlen > 256) {
          return ErrorCode::INVAL;
        }
        if (old == nullptr || oldlenp == nullptr) {
          return ErrorCode::INVAL;
        }

        // Check if old buffer size is valid
        size_t oldlen_check;
        ORBIS_RET_ON_ERROR(uread(oldlen_check, oldlenp));
        if (oldlen_check == 0) {
          return ErrorCode::INVAL;
        }

        // Read the sysctl name string from guest memory
        std::string searchNameStr(newlen, '\0');
        for (size_t i = 0; i < newlen; ++i) {
          char ch;
          if (auto result = uread(ch, (ptr<char>)new_ + i); result != ErrorCode{}) {
            return result;
          }
          searchNameStr[i] = ch;
        }
        auto searchName = std::string_view(searchNameStr);
        // std::fprintf(stderr, "   unspec - get name of '%s'\n", searchName.data());
        // Use a local buffer to build the OID, then write to guest memory
        std::uint32_t oid_buffer[16];  // Max OID length
        std::uint32_t count = 0;

        if (searchName == "kern.smp.cpus") {
          if (safeOldLen < 2 * sizeof(uint32_t)) {
            std::fprintf(stderr, "   %s error\n", searchName.data());
            return ErrorCode::INVAL;
          }

          oid_buffer[count++] = kern;
          oid_buffer[count++] = smp_cpus;
        } else if (searchName == "machdep.tsc_freq") {
          if (safeOldLen < 2 * sizeof(uint32_t)) {
            std::fprintf(stderr, "   %s error\n", searchName.data());
            return ErrorCode::INVAL;
          }

          oid_buffer[count++] = machdep;
          oid_buffer[count++] = tsc_freq;
        } else if (searchName == "kern.sdk_version") {
          if (safeOldLen < 2 * sizeof(uint32_t)) {
            std::fprintf(stderr, "   %s error\n", searchName.data());
            return ErrorCode::INVAL;
          }

          oid_buffer[count++] = kern;
          oid_buffer[count++] = sdk_version;
        } else if (searchName == "kern.rng_pseudo") {
          if (safeOldLen < 2 * sizeof(uint32_t)) {
            std::fprintf(stderr, "   %s error\n", searchName.data());
            return ErrorCode::INVAL;
          }

          oid_buffer[count++] = kern;
          oid_buffer[count++] = rng_pseudo;
        } else if (searchName == "kern.sched.cpusetsize") {
          if (safeOldLen < 2 * sizeof(uint32_t)) {
            std::fprintf(stderr, "   %s error\n", searchName.data());
            return ErrorCode::INVAL;
          }

          oid_buffer[count++] = kern;
          oid_buffer[count++] = sched_cpusetsize;
        } else if (searchName == "kern.proc.ptc") {
          if (safeOldLen < 2 * sizeof(uint32_t)) {
            std::fprintf(stderr, "   %s error\n", searchName.data());
            return ErrorCode::INVAL;
          }

          oid_buffer[count++] = kern;
          oid_buffer[count++] = proc_ptc;
        } else if (searchName == "kern.cpumode") {
          if (safeOldLen < 2 * sizeof(uint32_t)) {
            std::fprintf(stderr, "   %s error\n", searchName.data());
            return ErrorCode::INVAL;
          }

          oid_buffer[count++] = kern;
          oid_buffer[count++] = cpu_mode;
        } else if (searchName == "kern.backup_restore_mode") {
          if (safeOldLen < 2 * sizeof(uint32_t)) {
            std::fprintf(stderr, "   %s error\n", searchName.data());
            return ErrorCode::INVAL;
          }

          oid_buffer[count++] = kern;
          oid_buffer[count++] = backup_restore_mode;
        } else if (searchName == "kern.console") {
          if (safeOldLen < 2 * sizeof(uint32_t)) {
            std::fprintf(stderr, "   %s error\n", searchName.data());
            return ErrorCode::INVAL;
          }

          oid_buffer[count++] = kern;
          oid_buffer[count++] = console;
        } else if (searchName == "kern.init_safe_mode") {
          if (safeOldLen < 2 * sizeof(uint32_t)) {
            std::fprintf(stderr, "   %s error\n", searchName.data());
            return ErrorCode::INVAL;
          }

          oid_buffer[count++] = kern;
          oid_buffer[count++] = init_safe_mode;
        } else if (searchName == "hw.config.chassis_info") {
          if (safeOldLen < 3 * sizeof(uint32_t)) {
            std::fprintf(stderr, "   %s error\n", searchName.data());
            return ErrorCode::INVAL;
          }

          oid_buffer[count++] = hw;
          oid_buffer[count++] = config;
          oid_buffer[count++] = chassis_info;
        } else if (searchName == "machdep.liverpool.telemetry") {
          if (safeOldLen < 3 * sizeof(uint32_t)) {
            std::fprintf(stderr, "   %s error\n", searchName.data());
            return ErrorCode::INVAL;
          }

          oid_buffer[count++] = machdep;
          oid_buffer[count++] = liverpool;
          oid_buffer[count++] = telemetry;
        } else if (searchName == "machdep.liverpool.icc_max") {
          if (safeOldLen < 3 * sizeof(uint32_t)) {
            std::fprintf(stderr, "   %s error\n", searchName.data());
            return ErrorCode::INVAL;
          }

          oid_buffer[count++] = machdep;
          oid_buffer[count++] = liverpool;
          oid_buffer[count++] = icc_max;
        } else if (searchName == "vm.swap_avail") {
          if (safeOldLen < 2 * sizeof(uint32_t)) {
            std::fprintf(stderr, "   %s error\n", searchName.data());
            return ErrorCode::INVAL;
          }

          oid_buffer[count++] = vm;
          oid_buffer[count++] = swap_avail;
        } else if (searchName == "vm.kern_heap_size") {
          if (safeOldLen < 2 * sizeof(uint32_t)) {
            std::fprintf(stderr, "   %s error\n", searchName.data());
            return ErrorCode::INVAL;
          }

          oid_buffer[count++] = vm;
          oid_buffer[count++] = kern_heap_size;
        } else if (searchName == "vm.swap_total") {
          if (safeOldLen < 2 * sizeof(uint32_t)) {
            std::fprintf(stderr, "   %s error\n", searchName.data());
            return ErrorCode::INVAL;
          }

          oid_buffer[count++] = vm;
          oid_buffer[count++] = swap_total;
        } else if (searchName == "machdep.bootparams.is_main_on_standby") {
          if (safeOldLen < 3 * sizeof(uint32_t)) {
            std::fprintf(stderr, "   %s error\n", searchName.data());
            return ErrorCode::INVAL;
          }

          oid_buffer[count++] = machdep;
          oid_buffer[count++] = bootparams;
          oid_buffer[count++] = is_main_on_standby;
        } else if (searchName == "machdep.use_idle_hlt") {
          if (safeOldLen < 2 * sizeof(uint32_t)) {
            std::fprintf(stderr, "   %s error\n", searchName.data());
            return ErrorCode::INVAL;
          }

          oid_buffer[count++] = machdep;
          oid_buffer[count++] = use_idle_hlt;
        } else if (searchName == "hw.config.optical_out") {
          if (safeOldLen < 3 * sizeof(uint32_t)) {
            std::fprintf(stderr, "   %s error\n", searchName.data());
            return ErrorCode::INVAL;
          }

          oid_buffer[count++] = hw;
          oid_buffer[count++] = config;
          oid_buffer[count++] = optical_out;
        } else if (searchName == "machdep.idps") {
          if (safeOldLen < 2 * sizeof(uint32_t)) {
            std::fprintf(stderr, "   %s error\n", searchName.data());
            return ErrorCode::INVAL;
          }

          oid_buffer[count++] = machdep;
          oid_buffer[count++] = idps;
        } else if (searchName == "kern.geom.updtfmt") {
          if (safeOldLen < 3 * sizeof(uint32_t)) {
            std::fprintf(stderr, "   %s error\n", searchName.data());
            return ErrorCode::INVAL;
          }

          oid_buffer[count++] = kern;
          oid_buffer[count++] = geom;
          oid_buffer[count++] = updtfmt;
        } else if (searchName == "machdep.openpsid_for_sys") {
          if (safeOldLen < 2 * sizeof(uint32_t)) {
            std::fprintf(stderr, "   %s error\n", searchName.data());
            return ErrorCode::INVAL;
          }

          oid_buffer[count++] = machdep;
          oid_buffer[count++] = openpsid_for_sys;
        } else if (searchName == "machdep.sceKernelIsCavern") {
          if (safeOldLen < 2 * sizeof(uint32_t)) {
            std::fprintf(stderr, "   %s error\n", searchName.data());
            return ErrorCode::INVAL;
          }

          oid_buffer[count++] = machdep;
          oid_buffer[count++] = sceKernelIsCavern;
        } else if (searchName == "vm.budgets.mlock_total") {
          if (safeOldLen < 3 * sizeof(uint32_t)) {
            std::fprintf(stderr, "   %s error\n", searchName.data());
            return ErrorCode::INVAL;
          }

          oid_buffer[count++] = vm;
          oid_buffer[count++] = budgets;
          oid_buffer[count++] = mlock_total;
        } else if (searchName == "vm.budgets.mlock_avail") {
          if (safeOldLen < 3 * sizeof(uint32_t)) {
            std::fprintf(stderr, "   %s error\n", searchName.data());
            return ErrorCode::INVAL;
          }

          oid_buffer[count++] = vm;
          oid_buffer[count++] = budgets;
          oid_buffer[count++] = mlock_avail;
        } else if (searchName == "hw.sce_main_socid") {
          if (g_context->fwType != FwType::Ps5) {
            return ErrorCode::INVAL;
          }

          if (safeOldLen < 2 * sizeof(uint32_t)) {
            std::fprintf(stderr, "   %s error\n", searchName.data());
            return ErrorCode::INVAL;
          }

          oid_buffer[count++] = hw;
          oid_buffer[count++] = sce_main_socid;
        } else if (searchName == "dev.cpu.0.freq") {
          if (safeOldLen < 4 * sizeof(uint32_t)) {
            std::fprintf(stderr, "   %s error\n", searchName.data());
            return ErrorCode::INVAL;
          }

          oid_buffer[count++] = dev;
          oid_buffer[count++] = cpu;
          oid_buffer[count++] = 0;  // cpu index 0
          oid_buffer[count++] = freq;
        }

        if (count == 0) {
          std::fprintf(stderr, "sys___sysctl:   %s is unknown\n",
                       searchName.data());
          return ErrorCode::SRCH;
        }

        // Write the OID buffer to guest memory
        for (uint32_t i = 0; i < count; ++i) {
          ORBIS_RET_ON_ERROR(uwrite(ptr<uint32_t>(old) + i, oid_buffer[i]));
        }

        // Write the length back to guest
        size_t result_len = count * sizeof(uint32_t);
        ORBIS_RET_ON_ERROR(uwrite(oldlenp, result_len));
        return {};
      }

      default:
        break;
      }
      std::printf("   unspec_%u\n", name[1]);
      return {};
    }

    case sysctl_ctl::kern:
      switch (name[1]) {
      case sysctl_kern::boottime: {
        // FIXME: implement boottime support
        if (safeOldLen < sizeof(timeval) || new_ != nullptr || newlen != 0) {
          return ErrorCode::INVAL;
        }

        safeOldLen = sizeof(timeval);
        *ptr<timeval>(old) = {
            .tv_sec = 60,
            .tv_usec = 0,
        };
        return {};
      }
      case sysctl_kern::usrstack: {
        if (safeOldLen != 8 || new_ != nullptr || newlen != 0) {
          return ErrorCode::INVAL;
        }

        std::printf("Reporting stack at %p\n", thread->stackEnd);
        *(ptr<void> *)old = thread->stackEnd;
        return {};
      }

      case sysctl_kern::smp_cpus:
        if (safeOldLen != 4 || new_ != nullptr || newlen != 0) {
          return ErrorCode::INVAL;
        }

        *(uint32_t *)old = 6;
        return {};

      case sysctl_kern::sdk_version: {
        if (safeOldLen != 4 || new_ != nullptr || newlen != 0) {
          return ErrorCode::INVAL;
        }

        std::printf("Reporting SDK version %x\n", thread->tproc->sdkVersion);
        *(uint32_t *)old = thread->tproc->sdkVersion;
        return {};
      }

      case sysctl_kern::sched_cpusetsize:
        if (safeOldLen != 4 || new_ != nullptr || newlen != 0) {
          return ErrorCode::INVAL;
        }

        ORBIS_RET_ON_ERROR(uwrite(ptr<std::uint32_t>(old), 4u));
        return {};

      case sysctl_kern::rng_pseudo:
        if (safeOldLen != 0x40 || new_ != nullptr || newlen != 0) {
          return ErrorCode::INVAL;
        }

        std::memset(old, 0, 0x40);
        return {};

      case sysctl_kern::arnd: {
        struct kern37_value {
          std::uint64_t size;
          std::uint64_t unk[7];
        };

        if (safeOldLen != sizeof(kern37_value) || new_ != nullptr ||
            newlen != 0) {
          return ErrorCode::INVAL;
        }

        auto value = (kern37_value *)old;
        value->size = sizeof(kern37_value);
        return {};
      }

      case sysctl_kern::proc_ptc: {
        if (safeOldLen != 8 || new_ != nullptr || newlen != 0) {
          return ErrorCode::INVAL;
        }

        *(std::uint64_t *)old = 1357;
        return {};
      }

      case sysctl_kern::cpu_mode: {
        if (safeOldLen != 4 || new_ != nullptr || newlen != 0) {
          return ErrorCode::INVAL;
        }

        // 0 - 6 cpu
        // 1 - 7 cpu, low power
        // 5 - 7 cpu, normal
        *(std::uint32_t *)old = 5;
        return {};
      }

      case sysctl_kern::backup_restore_mode:
        if (safeOldLen != 4 || new_ != nullptr || newlen != 0) {
          return ErrorCode::INVAL;
        }

        // 0 - normal
        // 1 - backup
        // 2 - restore
        *(std::uint32_t *)old = 0;
        return {};

      case sysctl_kern::init_safe_mode:
        if (old && oldlenp) {
          ORBIS_LOG_ERROR("sysctl: get kern.init_safe_mode", oldlenp, new_,
                          newlen);
          if (safeOldLen != 4) {
            return ErrorCode::INVAL;
          }

          *(std::uint32_t *)old = g_context->safeMode;
        }
        if (new_ != nullptr && newlen == 4) {
          ORBIS_LOG_ERROR("sysctl: set kern.init_safe_mode",
                          *(std::uint32_t *)new_, newlen);
        }
        return {};

      default:
        return ErrorCode::INVAL;
      }
      break;

    case sysctl_ctl::vm:
      switch (name[1]) {
      case sysctl_vm::kern_heap_size:
        if (safeOldLen != 4 || new_ != nullptr || newlen != 0) {
          return ErrorCode::INVAL;
        }

        *(std::uint32_t *)old = (1 << 14) >> 14;
        return {};

      case sysctl_vm::swap_total:
        if (safeOldLen != 8 || new_ != nullptr || newlen != 0) {
          return ErrorCode::INVAL;
        }

        *(std::uint64_t *)old = 0;
        return {};

      case sysctl_vm::swap_avail:
        if (safeOldLen != 4 || new_ != nullptr || newlen != 0) {
          return ErrorCode::INVAL;
        }

        *(std::uint32_t *)old = (1 << 14) >> 14;
        return {};

      default:
        break;
      }
    case sysctl_ctl::vfs:
    case sysctl_ctl::net:
    case sysctl_ctl::debug:
      return ErrorCode::INVAL;

    case sysctl_ctl::hw:
      switch (name[1]) {
      case sysctl_hw::pagesize:
        if (safeOldLen != 4 || new_ != nullptr || newlen != 0) {
          return ErrorCode::INVAL;
        }

        *(uint32_t *)old = 0x4000;
        return {};

      case sysctl_hw::sce_main_socid:
        if (g_context->fwType != FwType::Ps5) {
          return ErrorCode::INVAL;
        }
        if (safeOldLen != 4 || new_ != nullptr || newlen != 0) {
          return ErrorCode::INVAL;
        }

        *(uint32_t *)old = 0x840f50;
        return {};

      case sysctl_hw::ncpu:
        if (safeOldLen != 4 || new_ != nullptr || newlen != 0) {

        } else {

          *(uint32_t *)old = 7;
          return {};
        }

      default:
        break;
      }
      break;

    case sysctl_ctl::machdep:
      switch (name[1]) {
      case sysctl_machdep::tsc_freq: {
        if (safeOldLen != 8 || new_ != nullptr || newlen != 0) {
          return ErrorCode::INVAL;
        }

        if (g_context->fwType != FwType::Ps5 &&
            std::string_view((char *)thread->tproc->appInfo.titleId) ==
                "NPXS20973") {
          ORBIS_LOG_ERROR("get tsc freq: returning patched value");
          *(uint64_t *)old = 1000000;
        } else {
          *(uint64_t *)old = g_context->getTscFreq();
        }
        return {};
      }

      case sysctl_machdep::idps: {
        if (safeOldLen != 16 || new_ != nullptr || newlen != 0) {
          return ErrorCode::INVAL;
        }

        std::memset(old, 0, 16);
        return uwrite<short>((short *)((char *)old + 4), 0x8401);
      }

      case sysctl_machdep::openpsid_for_sys: {
        if (safeOldLen != 16 || new_ != nullptr || newlen != 0) {
          return ErrorCode::INVAL;
        }

        std::memset(old, 0, 16);
        return {};
      }

      case sysctl_machdep::sceKernelIsCavern: {
        if (safeOldLen != 4 || new_ != nullptr || newlen != 0) {
          return ErrorCode::INVAL;
        }

        *(uint32_t *)old = 1;
        return {};
      }

      default:
        break;
      }
    case sysctl_ctl::user:
      break;
    }
  }

  std::string concatName;
  for (unsigned int i = 0; i < namelen; ++i) {
    if (i != 0) {
      concatName += '.';
    }
    concatName += std::to_string(name[i]);
  }

  // oldlenp now points to safeOldLen (already read at start)
  std::size_t oldLen = oldlenp ? safeOldLen : 0;
  ORBIS_LOG_TODO(__FUNCTION__, concatName, oldLen, new_, newlen);
  thread->where();

  // Return error for unimplemented sysctls instead of success
  // Returning success makes guest think sysctl worked and try to use uninitialized data
  return ErrorCode::NOENT;  // Sysctl not found
}
} // namespace orbis

orbis::SysResult orbis::sys___sysctl(Thread *thread, ptr<sint> name,
                                     uint namelen, ptr<void> old,
                                     ptr<size_t> oldlenp, ptr<void> new_,
                                     size_t newlen) {

  auto result = kern_sysctl(thread, name, namelen, old, oldlenp, new_, newlen);

  if (result.isError()) {
    std::string concatName;
    for (unsigned int i = 0; i < namelen; ++i) {
      if (i != 0) {
        concatName += '.';
      }

      concatName += std::to_string(name[i]);
    }

    std::size_t oldLen = 0;
    if (oldlenp) {
      uread(oldLen, oldlenp);
    }
    ORBIS_LOG_TODO(__FUNCTION__, concatName, oldLen, new_, newlen);
    thread->where();
  }

  return result;
}