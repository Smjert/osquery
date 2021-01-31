#include "users.h"

#include <cerrno>
#include <osquery/utils/status/status.h>

Status getUserInformationFromUsername(const std::string& username,
                                      UserInfo& user_info) {
  if (user_info.strings_buffer.empty()) {
    return Status::failure("Cannot store passwd strings, buffer is empty");
  }

  struct passwd* result_passwd;
  auto error = getpwnam_r(username.c_str(),
                          &user_info.data,
                          &user_info.strings_buffer[0],
                          user_info.strings_buffer.size(),
                          &result_passwd);

  if (error < 0) {
    return Status::failure("Failed to get user with username " + username +
                           ", error " + std::to_string(errno));
  }

  if (error == 0 && result_passwd == nullptr) {
    return Status::failure(2, "No user found with username " + username);
  }

  return Status::success();
}

Status getUserInformationFromUid(uid_t uid, UserInfo& user_info) {
  if (user_info.strings_buffer.empty()) {
    return Status::failure("Cannot store passwd strings, buffer is empty");
  }

  struct passwd* result_passwd;
  auto error = getpwuid_r(uid,
                          user_info.data,
                          &user_info.strings_buffer[0],
                          user_info.strings_buffer.size(),
                          &result_passwd);

  if (error < 0) {
    return Status::failure("Failed to get user with uid " +
                           std::to_string(uid) + ", error " +
                           std::to_string(errno));
  }

  if (error == 0 && result_passwd == nullptr) {
    return Status::failure(
        2, "No user found with username " + std::to_string(uid));
  }

  return Status::success();
}

Status getAllUsersInformation(std::vector<UserInfo>& users_info) {}
