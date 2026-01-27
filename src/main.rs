use std::os::raw::c_int;

unsafe extern "C" {
  fn print_hello() -> c_int;
}

fn main() {
  unsafe {
    print_hello();
  }
}
