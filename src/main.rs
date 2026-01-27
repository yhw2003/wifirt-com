use std::os::raw::c_int;

unsafe extern "C" {
  fn start_demo() -> c_int;
}

fn main() {
  unsafe {
    start_demo();
  }
}
