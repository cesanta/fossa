print('Initializing net skeleton scripting...', '\n');

var ev_handler = function(conn, ev, param) {
  print('JS handler: conn=', conn, ', ev=', ev, ', param: ', param, '\n');
  if (ev == 3) {
    print('received data: ', conn.recv_buf, '\n');
    conn.write('HTTP/1.0 200 OK\n\n', conn.recv_buf);
    conn.close()
  }
  if (ev == 5) {
    print('disconnected.', '\n');
  }
  return 0;
};
