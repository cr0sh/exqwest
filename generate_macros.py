inner = ""
for i in range(33):
    inner += "    (\n"

    for j in range(1, i + 1):
        if j == 1:
            inner += f"        $(#[$meta{j}:meta])*\n"
        else:
            inner += f"        ,$(#[$meta{j}:meta])*\n"
        inner += f"        $key{j}:ident: $value{j}:expr\n"

    if i != 0:
        inner += "        $(,)?\n"
    inner += "    ) => {{\n"

    if i == 0:
        typarams = ""
    else:
        typarams = "<" + ", ".join(map(lambda x: f"T{x}", range(1, i + 1))) + ">"

    inner += """        use $crate::__private::serde;
        #[derive(serde::Serialize)]
        #[allow(non_snake_case)]
    """
    inner += f"        struct Serializable{typarams}{{\n"

    for j in range(1, i + 1):
        inner += f"            $(#[$meta{j}])*\n"
        inner += f"            $key{j}: T{j},\n"

    inner += "        }\n"

    inner += "        Serializable {\n"

    for j in range(1, i + 1):
        inner += f"            $key{j}: $value{j},\n"

    inner += "        }\n"

    inner += "    }};\n\n"


output = """
/// # Examples
/// ```
/// # use exqwest::serializable;
/// let _ = serializable! {{
///     foo: "bar",
/// }};
/// ````
#[macro_export]
macro_rules! serializable {{
    {}
}}
""".format(
    inner.strip()
)

import sys

sys.stdout.write(output)
