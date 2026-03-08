pub enum LineKind {}
pub struct RawLine<'a> {
    _marker: std::marker::PhantomData<&'a str>,
}
pub fn parse_line(_line: &str) -> RawLine<'_> {
    todo!()
}
