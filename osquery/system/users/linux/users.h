#include <pwd.h>
#include <string>
#include <unistd.h>
#include <vector>

#include <osquery/utils/status/status.h>

struct LinuxUserInfo {
  LinuxUserInfo();
  struct passwd data;
  std::vector<char> strings_buffer;
};

using UserInfo = LinuxUserInfo;

Status getUserInformationFromUsername(const std::string& username,
                                      UserInfo user_info);
Status getUserInformationFromUid(uid_t uid, UserInfo& user_info);
Status getAllUsersInformation(std::vector<UserInfo>& users_info);
