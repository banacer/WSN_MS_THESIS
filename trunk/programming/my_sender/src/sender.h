#ifndef SENDER_H
#define SENDER_H

#endif /* SENDER_H */

typedef nx_struct SenderMsg {
  nx_uint16_t nodeid;
  nx_uint16_t consumption;
} SenderMsg;

typedef nx_struct ErrorMsg {
  nx_uint16_t nodeid;
  nx_uint16_t error;
} ErrorMsg;