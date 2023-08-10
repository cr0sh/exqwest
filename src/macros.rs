/// # Examples
/// ```
/// # use exqwest::serializable;
/// let _ = serializable! {
///     foo: "bar",
/// };
/// ````
#[macro_export]
macro_rules! serializable {
    (
    ) => {{
        use $crate::__private::serde;
        #[derive(serde::Serialize)]
        #[allow(non_snake_case)]
            struct Serializable{
        }
        Serializable {
        }
    }};

    (
        $(#[$meta1:meta])*
        $key1:ident: $value1:expr
        $(,)?
    ) => {{
        use $crate::__private::serde;
        #[derive(serde::Serialize)]
        #[allow(non_snake_case)]
            struct Serializable<T1>{
            $(#[$meta1])*
            $key1: T1,
        }
        Serializable {
            $key1: $value1,
        }
    }};

    (
        $(#[$meta1:meta])*
        $key1:ident: $value1:expr
        ,$(#[$meta2:meta])*
        $key2:ident: $value2:expr
        $(,)?
    ) => {{
        use $crate::__private::serde;
        #[derive(serde::Serialize)]
        #[allow(non_snake_case)]
            struct Serializable<T1, T2>{
            $(#[$meta1])*
            $key1: T1,
            $(#[$meta2])*
            $key2: T2,
        }
        Serializable {
            $key1: $value1,
            $key2: $value2,
        }
    }};

    (
        $(#[$meta1:meta])*
        $key1:ident: $value1:expr
        ,$(#[$meta2:meta])*
        $key2:ident: $value2:expr
        ,$(#[$meta3:meta])*
        $key3:ident: $value3:expr
        $(,)?
    ) => {{
        use $crate::__private::serde;
        #[derive(serde::Serialize)]
        #[allow(non_snake_case)]
            struct Serializable<T1, T2, T3>{
            $(#[$meta1])*
            $key1: T1,
            $(#[$meta2])*
            $key2: T2,
            $(#[$meta3])*
            $key3: T3,
        }
        Serializable {
            $key1: $value1,
            $key2: $value2,
            $key3: $value3,
        }
    }};

    (
        $(#[$meta1:meta])*
        $key1:ident: $value1:expr
        ,$(#[$meta2:meta])*
        $key2:ident: $value2:expr
        ,$(#[$meta3:meta])*
        $key3:ident: $value3:expr
        ,$(#[$meta4:meta])*
        $key4:ident: $value4:expr
        $(,)?
    ) => {{
        use $crate::__private::serde;
        #[derive(serde::Serialize)]
        #[allow(non_snake_case)]
            struct Serializable<T1, T2, T3, T4>{
            $(#[$meta1])*
            $key1: T1,
            $(#[$meta2])*
            $key2: T2,
            $(#[$meta3])*
            $key3: T3,
            $(#[$meta4])*
            $key4: T4,
        }
        Serializable {
            $key1: $value1,
            $key2: $value2,
            $key3: $value3,
            $key4: $value4,
        }
    }};

    (
        $(#[$meta1:meta])*
        $key1:ident: $value1:expr
        ,$(#[$meta2:meta])*
        $key2:ident: $value2:expr
        ,$(#[$meta3:meta])*
        $key3:ident: $value3:expr
        ,$(#[$meta4:meta])*
        $key4:ident: $value4:expr
        ,$(#[$meta5:meta])*
        $key5:ident: $value5:expr
        $(,)?
    ) => {{
        use $crate::__private::serde;
        #[derive(serde::Serialize)]
        #[allow(non_snake_case)]
            struct Serializable<T1, T2, T3, T4, T5>{
            $(#[$meta1])*
            $key1: T1,
            $(#[$meta2])*
            $key2: T2,
            $(#[$meta3])*
            $key3: T3,
            $(#[$meta4])*
            $key4: T4,
            $(#[$meta5])*
            $key5: T5,
        }
        Serializable {
            $key1: $value1,
            $key2: $value2,
            $key3: $value3,
            $key4: $value4,
            $key5: $value5,
        }
    }};

    (
        $(#[$meta1:meta])*
        $key1:ident: $value1:expr
        ,$(#[$meta2:meta])*
        $key2:ident: $value2:expr
        ,$(#[$meta3:meta])*
        $key3:ident: $value3:expr
        ,$(#[$meta4:meta])*
        $key4:ident: $value4:expr
        ,$(#[$meta5:meta])*
        $key5:ident: $value5:expr
        ,$(#[$meta6:meta])*
        $key6:ident: $value6:expr
        $(,)?
    ) => {{
        use $crate::__private::serde;
        #[derive(serde::Serialize)]
        #[allow(non_snake_case)]
            struct Serializable<T1, T2, T3, T4, T5, T6>{
            $(#[$meta1])*
            $key1: T1,
            $(#[$meta2])*
            $key2: T2,
            $(#[$meta3])*
            $key3: T3,
            $(#[$meta4])*
            $key4: T4,
            $(#[$meta5])*
            $key5: T5,
            $(#[$meta6])*
            $key6: T6,
        }
        Serializable {
            $key1: $value1,
            $key2: $value2,
            $key3: $value3,
            $key4: $value4,
            $key5: $value5,
            $key6: $value6,
        }
    }};

    (
        $(#[$meta1:meta])*
        $key1:ident: $value1:expr
        ,$(#[$meta2:meta])*
        $key2:ident: $value2:expr
        ,$(#[$meta3:meta])*
        $key3:ident: $value3:expr
        ,$(#[$meta4:meta])*
        $key4:ident: $value4:expr
        ,$(#[$meta5:meta])*
        $key5:ident: $value5:expr
        ,$(#[$meta6:meta])*
        $key6:ident: $value6:expr
        ,$(#[$meta7:meta])*
        $key7:ident: $value7:expr
        $(,)?
    ) => {{
        use $crate::__private::serde;
        #[derive(serde::Serialize)]
        #[allow(non_snake_case)]
            struct Serializable<T1, T2, T3, T4, T5, T6, T7>{
            $(#[$meta1])*
            $key1: T1,
            $(#[$meta2])*
            $key2: T2,
            $(#[$meta3])*
            $key3: T3,
            $(#[$meta4])*
            $key4: T4,
            $(#[$meta5])*
            $key5: T5,
            $(#[$meta6])*
            $key6: T6,
            $(#[$meta7])*
            $key7: T7,
        }
        Serializable {
            $key1: $value1,
            $key2: $value2,
            $key3: $value3,
            $key4: $value4,
            $key5: $value5,
            $key6: $value6,
            $key7: $value7,
        }
    }};

    (
        $(#[$meta1:meta])*
        $key1:ident: $value1:expr
        ,$(#[$meta2:meta])*
        $key2:ident: $value2:expr
        ,$(#[$meta3:meta])*
        $key3:ident: $value3:expr
        ,$(#[$meta4:meta])*
        $key4:ident: $value4:expr
        ,$(#[$meta5:meta])*
        $key5:ident: $value5:expr
        ,$(#[$meta6:meta])*
        $key6:ident: $value6:expr
        ,$(#[$meta7:meta])*
        $key7:ident: $value7:expr
        ,$(#[$meta8:meta])*
        $key8:ident: $value8:expr
        $(,)?
    ) => {{
        use $crate::__private::serde;
        #[derive(serde::Serialize)]
        #[allow(non_snake_case)]
            struct Serializable<T1, T2, T3, T4, T5, T6, T7, T8>{
            $(#[$meta1])*
            $key1: T1,
            $(#[$meta2])*
            $key2: T2,
            $(#[$meta3])*
            $key3: T3,
            $(#[$meta4])*
            $key4: T4,
            $(#[$meta5])*
            $key5: T5,
            $(#[$meta6])*
            $key6: T6,
            $(#[$meta7])*
            $key7: T7,
            $(#[$meta8])*
            $key8: T8,
        }
        Serializable {
            $key1: $value1,
            $key2: $value2,
            $key3: $value3,
            $key4: $value4,
            $key5: $value5,
            $key6: $value6,
            $key7: $value7,
            $key8: $value8,
        }
    }};

    (
        $(#[$meta1:meta])*
        $key1:ident: $value1:expr
        ,$(#[$meta2:meta])*
        $key2:ident: $value2:expr
        ,$(#[$meta3:meta])*
        $key3:ident: $value3:expr
        ,$(#[$meta4:meta])*
        $key4:ident: $value4:expr
        ,$(#[$meta5:meta])*
        $key5:ident: $value5:expr
        ,$(#[$meta6:meta])*
        $key6:ident: $value6:expr
        ,$(#[$meta7:meta])*
        $key7:ident: $value7:expr
        ,$(#[$meta8:meta])*
        $key8:ident: $value8:expr
        ,$(#[$meta9:meta])*
        $key9:ident: $value9:expr
        $(,)?
    ) => {{
        use $crate::__private::serde;
        #[derive(serde::Serialize)]
        #[allow(non_snake_case)]
            struct Serializable<T1, T2, T3, T4, T5, T6, T7, T8, T9>{
            $(#[$meta1])*
            $key1: T1,
            $(#[$meta2])*
            $key2: T2,
            $(#[$meta3])*
            $key3: T3,
            $(#[$meta4])*
            $key4: T4,
            $(#[$meta5])*
            $key5: T5,
            $(#[$meta6])*
            $key6: T6,
            $(#[$meta7])*
            $key7: T7,
            $(#[$meta8])*
            $key8: T8,
            $(#[$meta9])*
            $key9: T9,
        }
        Serializable {
            $key1: $value1,
            $key2: $value2,
            $key3: $value3,
            $key4: $value4,
            $key5: $value5,
            $key6: $value6,
            $key7: $value7,
            $key8: $value8,
            $key9: $value9,
        }
    }};

    (
        $(#[$meta1:meta])*
        $key1:ident: $value1:expr
        ,$(#[$meta2:meta])*
        $key2:ident: $value2:expr
        ,$(#[$meta3:meta])*
        $key3:ident: $value3:expr
        ,$(#[$meta4:meta])*
        $key4:ident: $value4:expr
        ,$(#[$meta5:meta])*
        $key5:ident: $value5:expr
        ,$(#[$meta6:meta])*
        $key6:ident: $value6:expr
        ,$(#[$meta7:meta])*
        $key7:ident: $value7:expr
        ,$(#[$meta8:meta])*
        $key8:ident: $value8:expr
        ,$(#[$meta9:meta])*
        $key9:ident: $value9:expr
        ,$(#[$meta10:meta])*
        $key10:ident: $value10:expr
        $(,)?
    ) => {{
        use $crate::__private::serde;
        #[derive(serde::Serialize)]
        #[allow(non_snake_case)]
            struct Serializable<T1, T2, T3, T4, T5, T6, T7, T8, T9, T10>{
            $(#[$meta1])*
            $key1: T1,
            $(#[$meta2])*
            $key2: T2,
            $(#[$meta3])*
            $key3: T3,
            $(#[$meta4])*
            $key4: T4,
            $(#[$meta5])*
            $key5: T5,
            $(#[$meta6])*
            $key6: T6,
            $(#[$meta7])*
            $key7: T7,
            $(#[$meta8])*
            $key8: T8,
            $(#[$meta9])*
            $key9: T9,
            $(#[$meta10])*
            $key10: T10,
        }
        Serializable {
            $key1: $value1,
            $key2: $value2,
            $key3: $value3,
            $key4: $value4,
            $key5: $value5,
            $key6: $value6,
            $key7: $value7,
            $key8: $value8,
            $key9: $value9,
            $key10: $value10,
        }
    }};

    (
        $(#[$meta1:meta])*
        $key1:ident: $value1:expr
        ,$(#[$meta2:meta])*
        $key2:ident: $value2:expr
        ,$(#[$meta3:meta])*
        $key3:ident: $value3:expr
        ,$(#[$meta4:meta])*
        $key4:ident: $value4:expr
        ,$(#[$meta5:meta])*
        $key5:ident: $value5:expr
        ,$(#[$meta6:meta])*
        $key6:ident: $value6:expr
        ,$(#[$meta7:meta])*
        $key7:ident: $value7:expr
        ,$(#[$meta8:meta])*
        $key8:ident: $value8:expr
        ,$(#[$meta9:meta])*
        $key9:ident: $value9:expr
        ,$(#[$meta10:meta])*
        $key10:ident: $value10:expr
        ,$(#[$meta11:meta])*
        $key11:ident: $value11:expr
        $(,)?
    ) => {{
        use $crate::__private::serde;
        #[derive(serde::Serialize)]
        #[allow(non_snake_case)]
            struct Serializable<T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11>{
            $(#[$meta1])*
            $key1: T1,
            $(#[$meta2])*
            $key2: T2,
            $(#[$meta3])*
            $key3: T3,
            $(#[$meta4])*
            $key4: T4,
            $(#[$meta5])*
            $key5: T5,
            $(#[$meta6])*
            $key6: T6,
            $(#[$meta7])*
            $key7: T7,
            $(#[$meta8])*
            $key8: T8,
            $(#[$meta9])*
            $key9: T9,
            $(#[$meta10])*
            $key10: T10,
            $(#[$meta11])*
            $key11: T11,
        }
        Serializable {
            $key1: $value1,
            $key2: $value2,
            $key3: $value3,
            $key4: $value4,
            $key5: $value5,
            $key6: $value6,
            $key7: $value7,
            $key8: $value8,
            $key9: $value9,
            $key10: $value10,
            $key11: $value11,
        }
    }};

    (
        $(#[$meta1:meta])*
        $key1:ident: $value1:expr
        ,$(#[$meta2:meta])*
        $key2:ident: $value2:expr
        ,$(#[$meta3:meta])*
        $key3:ident: $value3:expr
        ,$(#[$meta4:meta])*
        $key4:ident: $value4:expr
        ,$(#[$meta5:meta])*
        $key5:ident: $value5:expr
        ,$(#[$meta6:meta])*
        $key6:ident: $value6:expr
        ,$(#[$meta7:meta])*
        $key7:ident: $value7:expr
        ,$(#[$meta8:meta])*
        $key8:ident: $value8:expr
        ,$(#[$meta9:meta])*
        $key9:ident: $value9:expr
        ,$(#[$meta10:meta])*
        $key10:ident: $value10:expr
        ,$(#[$meta11:meta])*
        $key11:ident: $value11:expr
        ,$(#[$meta12:meta])*
        $key12:ident: $value12:expr
        $(,)?
    ) => {{
        use $crate::__private::serde;
        #[derive(serde::Serialize)]
        #[allow(non_snake_case)]
            struct Serializable<T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12>{
            $(#[$meta1])*
            $key1: T1,
            $(#[$meta2])*
            $key2: T2,
            $(#[$meta3])*
            $key3: T3,
            $(#[$meta4])*
            $key4: T4,
            $(#[$meta5])*
            $key5: T5,
            $(#[$meta6])*
            $key6: T6,
            $(#[$meta7])*
            $key7: T7,
            $(#[$meta8])*
            $key8: T8,
            $(#[$meta9])*
            $key9: T9,
            $(#[$meta10])*
            $key10: T10,
            $(#[$meta11])*
            $key11: T11,
            $(#[$meta12])*
            $key12: T12,
        }
        Serializable {
            $key1: $value1,
            $key2: $value2,
            $key3: $value3,
            $key4: $value4,
            $key5: $value5,
            $key6: $value6,
            $key7: $value7,
            $key8: $value8,
            $key9: $value9,
            $key10: $value10,
            $key11: $value11,
            $key12: $value12,
        }
    }};

    (
        $(#[$meta1:meta])*
        $key1:ident: $value1:expr
        ,$(#[$meta2:meta])*
        $key2:ident: $value2:expr
        ,$(#[$meta3:meta])*
        $key3:ident: $value3:expr
        ,$(#[$meta4:meta])*
        $key4:ident: $value4:expr
        ,$(#[$meta5:meta])*
        $key5:ident: $value5:expr
        ,$(#[$meta6:meta])*
        $key6:ident: $value6:expr
        ,$(#[$meta7:meta])*
        $key7:ident: $value7:expr
        ,$(#[$meta8:meta])*
        $key8:ident: $value8:expr
        ,$(#[$meta9:meta])*
        $key9:ident: $value9:expr
        ,$(#[$meta10:meta])*
        $key10:ident: $value10:expr
        ,$(#[$meta11:meta])*
        $key11:ident: $value11:expr
        ,$(#[$meta12:meta])*
        $key12:ident: $value12:expr
        ,$(#[$meta13:meta])*
        $key13:ident: $value13:expr
        $(,)?
    ) => {{
        use $crate::__private::serde;
        #[derive(serde::Serialize)]
        #[allow(non_snake_case)]
            struct Serializable<T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13>{
            $(#[$meta1])*
            $key1: T1,
            $(#[$meta2])*
            $key2: T2,
            $(#[$meta3])*
            $key3: T3,
            $(#[$meta4])*
            $key4: T4,
            $(#[$meta5])*
            $key5: T5,
            $(#[$meta6])*
            $key6: T6,
            $(#[$meta7])*
            $key7: T7,
            $(#[$meta8])*
            $key8: T8,
            $(#[$meta9])*
            $key9: T9,
            $(#[$meta10])*
            $key10: T10,
            $(#[$meta11])*
            $key11: T11,
            $(#[$meta12])*
            $key12: T12,
            $(#[$meta13])*
            $key13: T13,
        }
        Serializable {
            $key1: $value1,
            $key2: $value2,
            $key3: $value3,
            $key4: $value4,
            $key5: $value5,
            $key6: $value6,
            $key7: $value7,
            $key8: $value8,
            $key9: $value9,
            $key10: $value10,
            $key11: $value11,
            $key12: $value12,
            $key13: $value13,
        }
    }};

    (
        $(#[$meta1:meta])*
        $key1:ident: $value1:expr
        ,$(#[$meta2:meta])*
        $key2:ident: $value2:expr
        ,$(#[$meta3:meta])*
        $key3:ident: $value3:expr
        ,$(#[$meta4:meta])*
        $key4:ident: $value4:expr
        ,$(#[$meta5:meta])*
        $key5:ident: $value5:expr
        ,$(#[$meta6:meta])*
        $key6:ident: $value6:expr
        ,$(#[$meta7:meta])*
        $key7:ident: $value7:expr
        ,$(#[$meta8:meta])*
        $key8:ident: $value8:expr
        ,$(#[$meta9:meta])*
        $key9:ident: $value9:expr
        ,$(#[$meta10:meta])*
        $key10:ident: $value10:expr
        ,$(#[$meta11:meta])*
        $key11:ident: $value11:expr
        ,$(#[$meta12:meta])*
        $key12:ident: $value12:expr
        ,$(#[$meta13:meta])*
        $key13:ident: $value13:expr
        ,$(#[$meta14:meta])*
        $key14:ident: $value14:expr
        $(,)?
    ) => {{
        use $crate::__private::serde;
        #[derive(serde::Serialize)]
        #[allow(non_snake_case)]
            struct Serializable<T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14>{
            $(#[$meta1])*
            $key1: T1,
            $(#[$meta2])*
            $key2: T2,
            $(#[$meta3])*
            $key3: T3,
            $(#[$meta4])*
            $key4: T4,
            $(#[$meta5])*
            $key5: T5,
            $(#[$meta6])*
            $key6: T6,
            $(#[$meta7])*
            $key7: T7,
            $(#[$meta8])*
            $key8: T8,
            $(#[$meta9])*
            $key9: T9,
            $(#[$meta10])*
            $key10: T10,
            $(#[$meta11])*
            $key11: T11,
            $(#[$meta12])*
            $key12: T12,
            $(#[$meta13])*
            $key13: T13,
            $(#[$meta14])*
            $key14: T14,
        }
        Serializable {
            $key1: $value1,
            $key2: $value2,
            $key3: $value3,
            $key4: $value4,
            $key5: $value5,
            $key6: $value6,
            $key7: $value7,
            $key8: $value8,
            $key9: $value9,
            $key10: $value10,
            $key11: $value11,
            $key12: $value12,
            $key13: $value13,
            $key14: $value14,
        }
    }};

    (
        $(#[$meta1:meta])*
        $key1:ident: $value1:expr
        ,$(#[$meta2:meta])*
        $key2:ident: $value2:expr
        ,$(#[$meta3:meta])*
        $key3:ident: $value3:expr
        ,$(#[$meta4:meta])*
        $key4:ident: $value4:expr
        ,$(#[$meta5:meta])*
        $key5:ident: $value5:expr
        ,$(#[$meta6:meta])*
        $key6:ident: $value6:expr
        ,$(#[$meta7:meta])*
        $key7:ident: $value7:expr
        ,$(#[$meta8:meta])*
        $key8:ident: $value8:expr
        ,$(#[$meta9:meta])*
        $key9:ident: $value9:expr
        ,$(#[$meta10:meta])*
        $key10:ident: $value10:expr
        ,$(#[$meta11:meta])*
        $key11:ident: $value11:expr
        ,$(#[$meta12:meta])*
        $key12:ident: $value12:expr
        ,$(#[$meta13:meta])*
        $key13:ident: $value13:expr
        ,$(#[$meta14:meta])*
        $key14:ident: $value14:expr
        ,$(#[$meta15:meta])*
        $key15:ident: $value15:expr
        $(,)?
    ) => {{
        use $crate::__private::serde;
        #[derive(serde::Serialize)]
        #[allow(non_snake_case)]
            struct Serializable<T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14, T15>{
            $(#[$meta1])*
            $key1: T1,
            $(#[$meta2])*
            $key2: T2,
            $(#[$meta3])*
            $key3: T3,
            $(#[$meta4])*
            $key4: T4,
            $(#[$meta5])*
            $key5: T5,
            $(#[$meta6])*
            $key6: T6,
            $(#[$meta7])*
            $key7: T7,
            $(#[$meta8])*
            $key8: T8,
            $(#[$meta9])*
            $key9: T9,
            $(#[$meta10])*
            $key10: T10,
            $(#[$meta11])*
            $key11: T11,
            $(#[$meta12])*
            $key12: T12,
            $(#[$meta13])*
            $key13: T13,
            $(#[$meta14])*
            $key14: T14,
            $(#[$meta15])*
            $key15: T15,
        }
        Serializable {
            $key1: $value1,
            $key2: $value2,
            $key3: $value3,
            $key4: $value4,
            $key5: $value5,
            $key6: $value6,
            $key7: $value7,
            $key8: $value8,
            $key9: $value9,
            $key10: $value10,
            $key11: $value11,
            $key12: $value12,
            $key13: $value13,
            $key14: $value14,
            $key15: $value15,
        }
    }};

    (
        $(#[$meta1:meta])*
        $key1:ident: $value1:expr
        ,$(#[$meta2:meta])*
        $key2:ident: $value2:expr
        ,$(#[$meta3:meta])*
        $key3:ident: $value3:expr
        ,$(#[$meta4:meta])*
        $key4:ident: $value4:expr
        ,$(#[$meta5:meta])*
        $key5:ident: $value5:expr
        ,$(#[$meta6:meta])*
        $key6:ident: $value6:expr
        ,$(#[$meta7:meta])*
        $key7:ident: $value7:expr
        ,$(#[$meta8:meta])*
        $key8:ident: $value8:expr
        ,$(#[$meta9:meta])*
        $key9:ident: $value9:expr
        ,$(#[$meta10:meta])*
        $key10:ident: $value10:expr
        ,$(#[$meta11:meta])*
        $key11:ident: $value11:expr
        ,$(#[$meta12:meta])*
        $key12:ident: $value12:expr
        ,$(#[$meta13:meta])*
        $key13:ident: $value13:expr
        ,$(#[$meta14:meta])*
        $key14:ident: $value14:expr
        ,$(#[$meta15:meta])*
        $key15:ident: $value15:expr
        ,$(#[$meta16:meta])*
        $key16:ident: $value16:expr
        $(,)?
    ) => {{
        use $crate::__private::serde;
        #[derive(serde::Serialize)]
        #[allow(non_snake_case)]
            struct Serializable<T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14, T15, T16>{
            $(#[$meta1])*
            $key1: T1,
            $(#[$meta2])*
            $key2: T2,
            $(#[$meta3])*
            $key3: T3,
            $(#[$meta4])*
            $key4: T4,
            $(#[$meta5])*
            $key5: T5,
            $(#[$meta6])*
            $key6: T6,
            $(#[$meta7])*
            $key7: T7,
            $(#[$meta8])*
            $key8: T8,
            $(#[$meta9])*
            $key9: T9,
            $(#[$meta10])*
            $key10: T10,
            $(#[$meta11])*
            $key11: T11,
            $(#[$meta12])*
            $key12: T12,
            $(#[$meta13])*
            $key13: T13,
            $(#[$meta14])*
            $key14: T14,
            $(#[$meta15])*
            $key15: T15,
            $(#[$meta16])*
            $key16: T16,
        }
        Serializable {
            $key1: $value1,
            $key2: $value2,
            $key3: $value3,
            $key4: $value4,
            $key5: $value5,
            $key6: $value6,
            $key7: $value7,
            $key8: $value8,
            $key9: $value9,
            $key10: $value10,
            $key11: $value11,
            $key12: $value12,
            $key13: $value13,
            $key14: $value14,
            $key15: $value15,
            $key16: $value16,
        }
    }};

    (
        $(#[$meta1:meta])*
        $key1:ident: $value1:expr
        ,$(#[$meta2:meta])*
        $key2:ident: $value2:expr
        ,$(#[$meta3:meta])*
        $key3:ident: $value3:expr
        ,$(#[$meta4:meta])*
        $key4:ident: $value4:expr
        ,$(#[$meta5:meta])*
        $key5:ident: $value5:expr
        ,$(#[$meta6:meta])*
        $key6:ident: $value6:expr
        ,$(#[$meta7:meta])*
        $key7:ident: $value7:expr
        ,$(#[$meta8:meta])*
        $key8:ident: $value8:expr
        ,$(#[$meta9:meta])*
        $key9:ident: $value9:expr
        ,$(#[$meta10:meta])*
        $key10:ident: $value10:expr
        ,$(#[$meta11:meta])*
        $key11:ident: $value11:expr
        ,$(#[$meta12:meta])*
        $key12:ident: $value12:expr
        ,$(#[$meta13:meta])*
        $key13:ident: $value13:expr
        ,$(#[$meta14:meta])*
        $key14:ident: $value14:expr
        ,$(#[$meta15:meta])*
        $key15:ident: $value15:expr
        ,$(#[$meta16:meta])*
        $key16:ident: $value16:expr
        ,$(#[$meta17:meta])*
        $key17:ident: $value17:expr
        $(,)?
    ) => {{
        use $crate::__private::serde;
        #[derive(serde::Serialize)]
        #[allow(non_snake_case)]
            struct Serializable<T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14, T15, T16, T17>{
            $(#[$meta1])*
            $key1: T1,
            $(#[$meta2])*
            $key2: T2,
            $(#[$meta3])*
            $key3: T3,
            $(#[$meta4])*
            $key4: T4,
            $(#[$meta5])*
            $key5: T5,
            $(#[$meta6])*
            $key6: T6,
            $(#[$meta7])*
            $key7: T7,
            $(#[$meta8])*
            $key8: T8,
            $(#[$meta9])*
            $key9: T9,
            $(#[$meta10])*
            $key10: T10,
            $(#[$meta11])*
            $key11: T11,
            $(#[$meta12])*
            $key12: T12,
            $(#[$meta13])*
            $key13: T13,
            $(#[$meta14])*
            $key14: T14,
            $(#[$meta15])*
            $key15: T15,
            $(#[$meta16])*
            $key16: T16,
            $(#[$meta17])*
            $key17: T17,
        }
        Serializable {
            $key1: $value1,
            $key2: $value2,
            $key3: $value3,
            $key4: $value4,
            $key5: $value5,
            $key6: $value6,
            $key7: $value7,
            $key8: $value8,
            $key9: $value9,
            $key10: $value10,
            $key11: $value11,
            $key12: $value12,
            $key13: $value13,
            $key14: $value14,
            $key15: $value15,
            $key16: $value16,
            $key17: $value17,
        }
    }};

    (
        $(#[$meta1:meta])*
        $key1:ident: $value1:expr
        ,$(#[$meta2:meta])*
        $key2:ident: $value2:expr
        ,$(#[$meta3:meta])*
        $key3:ident: $value3:expr
        ,$(#[$meta4:meta])*
        $key4:ident: $value4:expr
        ,$(#[$meta5:meta])*
        $key5:ident: $value5:expr
        ,$(#[$meta6:meta])*
        $key6:ident: $value6:expr
        ,$(#[$meta7:meta])*
        $key7:ident: $value7:expr
        ,$(#[$meta8:meta])*
        $key8:ident: $value8:expr
        ,$(#[$meta9:meta])*
        $key9:ident: $value9:expr
        ,$(#[$meta10:meta])*
        $key10:ident: $value10:expr
        ,$(#[$meta11:meta])*
        $key11:ident: $value11:expr
        ,$(#[$meta12:meta])*
        $key12:ident: $value12:expr
        ,$(#[$meta13:meta])*
        $key13:ident: $value13:expr
        ,$(#[$meta14:meta])*
        $key14:ident: $value14:expr
        ,$(#[$meta15:meta])*
        $key15:ident: $value15:expr
        ,$(#[$meta16:meta])*
        $key16:ident: $value16:expr
        ,$(#[$meta17:meta])*
        $key17:ident: $value17:expr
        ,$(#[$meta18:meta])*
        $key18:ident: $value18:expr
        $(,)?
    ) => {{
        use $crate::__private::serde;
        #[derive(serde::Serialize)]
        #[allow(non_snake_case)]
            struct Serializable<T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14, T15, T16, T17, T18>{
            $(#[$meta1])*
            $key1: T1,
            $(#[$meta2])*
            $key2: T2,
            $(#[$meta3])*
            $key3: T3,
            $(#[$meta4])*
            $key4: T4,
            $(#[$meta5])*
            $key5: T5,
            $(#[$meta6])*
            $key6: T6,
            $(#[$meta7])*
            $key7: T7,
            $(#[$meta8])*
            $key8: T8,
            $(#[$meta9])*
            $key9: T9,
            $(#[$meta10])*
            $key10: T10,
            $(#[$meta11])*
            $key11: T11,
            $(#[$meta12])*
            $key12: T12,
            $(#[$meta13])*
            $key13: T13,
            $(#[$meta14])*
            $key14: T14,
            $(#[$meta15])*
            $key15: T15,
            $(#[$meta16])*
            $key16: T16,
            $(#[$meta17])*
            $key17: T17,
            $(#[$meta18])*
            $key18: T18,
        }
        Serializable {
            $key1: $value1,
            $key2: $value2,
            $key3: $value3,
            $key4: $value4,
            $key5: $value5,
            $key6: $value6,
            $key7: $value7,
            $key8: $value8,
            $key9: $value9,
            $key10: $value10,
            $key11: $value11,
            $key12: $value12,
            $key13: $value13,
            $key14: $value14,
            $key15: $value15,
            $key16: $value16,
            $key17: $value17,
            $key18: $value18,
        }
    }};

    (
        $(#[$meta1:meta])*
        $key1:ident: $value1:expr
        ,$(#[$meta2:meta])*
        $key2:ident: $value2:expr
        ,$(#[$meta3:meta])*
        $key3:ident: $value3:expr
        ,$(#[$meta4:meta])*
        $key4:ident: $value4:expr
        ,$(#[$meta5:meta])*
        $key5:ident: $value5:expr
        ,$(#[$meta6:meta])*
        $key6:ident: $value6:expr
        ,$(#[$meta7:meta])*
        $key7:ident: $value7:expr
        ,$(#[$meta8:meta])*
        $key8:ident: $value8:expr
        ,$(#[$meta9:meta])*
        $key9:ident: $value9:expr
        ,$(#[$meta10:meta])*
        $key10:ident: $value10:expr
        ,$(#[$meta11:meta])*
        $key11:ident: $value11:expr
        ,$(#[$meta12:meta])*
        $key12:ident: $value12:expr
        ,$(#[$meta13:meta])*
        $key13:ident: $value13:expr
        ,$(#[$meta14:meta])*
        $key14:ident: $value14:expr
        ,$(#[$meta15:meta])*
        $key15:ident: $value15:expr
        ,$(#[$meta16:meta])*
        $key16:ident: $value16:expr
        ,$(#[$meta17:meta])*
        $key17:ident: $value17:expr
        ,$(#[$meta18:meta])*
        $key18:ident: $value18:expr
        ,$(#[$meta19:meta])*
        $key19:ident: $value19:expr
        $(,)?
    ) => {{
        use $crate::__private::serde;
        #[derive(serde::Serialize)]
        #[allow(non_snake_case)]
            struct Serializable<T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14, T15, T16, T17, T18, T19>{
            $(#[$meta1])*
            $key1: T1,
            $(#[$meta2])*
            $key2: T2,
            $(#[$meta3])*
            $key3: T3,
            $(#[$meta4])*
            $key4: T4,
            $(#[$meta5])*
            $key5: T5,
            $(#[$meta6])*
            $key6: T6,
            $(#[$meta7])*
            $key7: T7,
            $(#[$meta8])*
            $key8: T8,
            $(#[$meta9])*
            $key9: T9,
            $(#[$meta10])*
            $key10: T10,
            $(#[$meta11])*
            $key11: T11,
            $(#[$meta12])*
            $key12: T12,
            $(#[$meta13])*
            $key13: T13,
            $(#[$meta14])*
            $key14: T14,
            $(#[$meta15])*
            $key15: T15,
            $(#[$meta16])*
            $key16: T16,
            $(#[$meta17])*
            $key17: T17,
            $(#[$meta18])*
            $key18: T18,
            $(#[$meta19])*
            $key19: T19,
        }
        Serializable {
            $key1: $value1,
            $key2: $value2,
            $key3: $value3,
            $key4: $value4,
            $key5: $value5,
            $key6: $value6,
            $key7: $value7,
            $key8: $value8,
            $key9: $value9,
            $key10: $value10,
            $key11: $value11,
            $key12: $value12,
            $key13: $value13,
            $key14: $value14,
            $key15: $value15,
            $key16: $value16,
            $key17: $value17,
            $key18: $value18,
            $key19: $value19,
        }
    }};

    (
        $(#[$meta1:meta])*
        $key1:ident: $value1:expr
        ,$(#[$meta2:meta])*
        $key2:ident: $value2:expr
        ,$(#[$meta3:meta])*
        $key3:ident: $value3:expr
        ,$(#[$meta4:meta])*
        $key4:ident: $value4:expr
        ,$(#[$meta5:meta])*
        $key5:ident: $value5:expr
        ,$(#[$meta6:meta])*
        $key6:ident: $value6:expr
        ,$(#[$meta7:meta])*
        $key7:ident: $value7:expr
        ,$(#[$meta8:meta])*
        $key8:ident: $value8:expr
        ,$(#[$meta9:meta])*
        $key9:ident: $value9:expr
        ,$(#[$meta10:meta])*
        $key10:ident: $value10:expr
        ,$(#[$meta11:meta])*
        $key11:ident: $value11:expr
        ,$(#[$meta12:meta])*
        $key12:ident: $value12:expr
        ,$(#[$meta13:meta])*
        $key13:ident: $value13:expr
        ,$(#[$meta14:meta])*
        $key14:ident: $value14:expr
        ,$(#[$meta15:meta])*
        $key15:ident: $value15:expr
        ,$(#[$meta16:meta])*
        $key16:ident: $value16:expr
        ,$(#[$meta17:meta])*
        $key17:ident: $value17:expr
        ,$(#[$meta18:meta])*
        $key18:ident: $value18:expr
        ,$(#[$meta19:meta])*
        $key19:ident: $value19:expr
        ,$(#[$meta20:meta])*
        $key20:ident: $value20:expr
        $(,)?
    ) => {{
        use $crate::__private::serde;
        #[derive(serde::Serialize)]
        #[allow(non_snake_case)]
            struct Serializable<T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14, T15, T16, T17, T18, T19, T20>{
            $(#[$meta1])*
            $key1: T1,
            $(#[$meta2])*
            $key2: T2,
            $(#[$meta3])*
            $key3: T3,
            $(#[$meta4])*
            $key4: T4,
            $(#[$meta5])*
            $key5: T5,
            $(#[$meta6])*
            $key6: T6,
            $(#[$meta7])*
            $key7: T7,
            $(#[$meta8])*
            $key8: T8,
            $(#[$meta9])*
            $key9: T9,
            $(#[$meta10])*
            $key10: T10,
            $(#[$meta11])*
            $key11: T11,
            $(#[$meta12])*
            $key12: T12,
            $(#[$meta13])*
            $key13: T13,
            $(#[$meta14])*
            $key14: T14,
            $(#[$meta15])*
            $key15: T15,
            $(#[$meta16])*
            $key16: T16,
            $(#[$meta17])*
            $key17: T17,
            $(#[$meta18])*
            $key18: T18,
            $(#[$meta19])*
            $key19: T19,
            $(#[$meta20])*
            $key20: T20,
        }
        Serializable {
            $key1: $value1,
            $key2: $value2,
            $key3: $value3,
            $key4: $value4,
            $key5: $value5,
            $key6: $value6,
            $key7: $value7,
            $key8: $value8,
            $key9: $value9,
            $key10: $value10,
            $key11: $value11,
            $key12: $value12,
            $key13: $value13,
            $key14: $value14,
            $key15: $value15,
            $key16: $value16,
            $key17: $value17,
            $key18: $value18,
            $key19: $value19,
            $key20: $value20,
        }
    }};

    (
        $(#[$meta1:meta])*
        $key1:ident: $value1:expr
        ,$(#[$meta2:meta])*
        $key2:ident: $value2:expr
        ,$(#[$meta3:meta])*
        $key3:ident: $value3:expr
        ,$(#[$meta4:meta])*
        $key4:ident: $value4:expr
        ,$(#[$meta5:meta])*
        $key5:ident: $value5:expr
        ,$(#[$meta6:meta])*
        $key6:ident: $value6:expr
        ,$(#[$meta7:meta])*
        $key7:ident: $value7:expr
        ,$(#[$meta8:meta])*
        $key8:ident: $value8:expr
        ,$(#[$meta9:meta])*
        $key9:ident: $value9:expr
        ,$(#[$meta10:meta])*
        $key10:ident: $value10:expr
        ,$(#[$meta11:meta])*
        $key11:ident: $value11:expr
        ,$(#[$meta12:meta])*
        $key12:ident: $value12:expr
        ,$(#[$meta13:meta])*
        $key13:ident: $value13:expr
        ,$(#[$meta14:meta])*
        $key14:ident: $value14:expr
        ,$(#[$meta15:meta])*
        $key15:ident: $value15:expr
        ,$(#[$meta16:meta])*
        $key16:ident: $value16:expr
        ,$(#[$meta17:meta])*
        $key17:ident: $value17:expr
        ,$(#[$meta18:meta])*
        $key18:ident: $value18:expr
        ,$(#[$meta19:meta])*
        $key19:ident: $value19:expr
        ,$(#[$meta20:meta])*
        $key20:ident: $value20:expr
        ,$(#[$meta21:meta])*
        $key21:ident: $value21:expr
        $(,)?
    ) => {{
        use $crate::__private::serde;
        #[derive(serde::Serialize)]
        #[allow(non_snake_case)]
            struct Serializable<T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14, T15, T16, T17, T18, T19, T20, T21>{
            $(#[$meta1])*
            $key1: T1,
            $(#[$meta2])*
            $key2: T2,
            $(#[$meta3])*
            $key3: T3,
            $(#[$meta4])*
            $key4: T4,
            $(#[$meta5])*
            $key5: T5,
            $(#[$meta6])*
            $key6: T6,
            $(#[$meta7])*
            $key7: T7,
            $(#[$meta8])*
            $key8: T8,
            $(#[$meta9])*
            $key9: T9,
            $(#[$meta10])*
            $key10: T10,
            $(#[$meta11])*
            $key11: T11,
            $(#[$meta12])*
            $key12: T12,
            $(#[$meta13])*
            $key13: T13,
            $(#[$meta14])*
            $key14: T14,
            $(#[$meta15])*
            $key15: T15,
            $(#[$meta16])*
            $key16: T16,
            $(#[$meta17])*
            $key17: T17,
            $(#[$meta18])*
            $key18: T18,
            $(#[$meta19])*
            $key19: T19,
            $(#[$meta20])*
            $key20: T20,
            $(#[$meta21])*
            $key21: T21,
        }
        Serializable {
            $key1: $value1,
            $key2: $value2,
            $key3: $value3,
            $key4: $value4,
            $key5: $value5,
            $key6: $value6,
            $key7: $value7,
            $key8: $value8,
            $key9: $value9,
            $key10: $value10,
            $key11: $value11,
            $key12: $value12,
            $key13: $value13,
            $key14: $value14,
            $key15: $value15,
            $key16: $value16,
            $key17: $value17,
            $key18: $value18,
            $key19: $value19,
            $key20: $value20,
            $key21: $value21,
        }
    }};

    (
        $(#[$meta1:meta])*
        $key1:ident: $value1:expr
        ,$(#[$meta2:meta])*
        $key2:ident: $value2:expr
        ,$(#[$meta3:meta])*
        $key3:ident: $value3:expr
        ,$(#[$meta4:meta])*
        $key4:ident: $value4:expr
        ,$(#[$meta5:meta])*
        $key5:ident: $value5:expr
        ,$(#[$meta6:meta])*
        $key6:ident: $value6:expr
        ,$(#[$meta7:meta])*
        $key7:ident: $value7:expr
        ,$(#[$meta8:meta])*
        $key8:ident: $value8:expr
        ,$(#[$meta9:meta])*
        $key9:ident: $value9:expr
        ,$(#[$meta10:meta])*
        $key10:ident: $value10:expr
        ,$(#[$meta11:meta])*
        $key11:ident: $value11:expr
        ,$(#[$meta12:meta])*
        $key12:ident: $value12:expr
        ,$(#[$meta13:meta])*
        $key13:ident: $value13:expr
        ,$(#[$meta14:meta])*
        $key14:ident: $value14:expr
        ,$(#[$meta15:meta])*
        $key15:ident: $value15:expr
        ,$(#[$meta16:meta])*
        $key16:ident: $value16:expr
        ,$(#[$meta17:meta])*
        $key17:ident: $value17:expr
        ,$(#[$meta18:meta])*
        $key18:ident: $value18:expr
        ,$(#[$meta19:meta])*
        $key19:ident: $value19:expr
        ,$(#[$meta20:meta])*
        $key20:ident: $value20:expr
        ,$(#[$meta21:meta])*
        $key21:ident: $value21:expr
        ,$(#[$meta22:meta])*
        $key22:ident: $value22:expr
        $(,)?
    ) => {{
        use $crate::__private::serde;
        #[derive(serde::Serialize)]
        #[allow(non_snake_case)]
            struct Serializable<T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14, T15, T16, T17, T18, T19, T20, T21, T22>{
            $(#[$meta1])*
            $key1: T1,
            $(#[$meta2])*
            $key2: T2,
            $(#[$meta3])*
            $key3: T3,
            $(#[$meta4])*
            $key4: T4,
            $(#[$meta5])*
            $key5: T5,
            $(#[$meta6])*
            $key6: T6,
            $(#[$meta7])*
            $key7: T7,
            $(#[$meta8])*
            $key8: T8,
            $(#[$meta9])*
            $key9: T9,
            $(#[$meta10])*
            $key10: T10,
            $(#[$meta11])*
            $key11: T11,
            $(#[$meta12])*
            $key12: T12,
            $(#[$meta13])*
            $key13: T13,
            $(#[$meta14])*
            $key14: T14,
            $(#[$meta15])*
            $key15: T15,
            $(#[$meta16])*
            $key16: T16,
            $(#[$meta17])*
            $key17: T17,
            $(#[$meta18])*
            $key18: T18,
            $(#[$meta19])*
            $key19: T19,
            $(#[$meta20])*
            $key20: T20,
            $(#[$meta21])*
            $key21: T21,
            $(#[$meta22])*
            $key22: T22,
        }
        Serializable {
            $key1: $value1,
            $key2: $value2,
            $key3: $value3,
            $key4: $value4,
            $key5: $value5,
            $key6: $value6,
            $key7: $value7,
            $key8: $value8,
            $key9: $value9,
            $key10: $value10,
            $key11: $value11,
            $key12: $value12,
            $key13: $value13,
            $key14: $value14,
            $key15: $value15,
            $key16: $value16,
            $key17: $value17,
            $key18: $value18,
            $key19: $value19,
            $key20: $value20,
            $key21: $value21,
            $key22: $value22,
        }
    }};

    (
        $(#[$meta1:meta])*
        $key1:ident: $value1:expr
        ,$(#[$meta2:meta])*
        $key2:ident: $value2:expr
        ,$(#[$meta3:meta])*
        $key3:ident: $value3:expr
        ,$(#[$meta4:meta])*
        $key4:ident: $value4:expr
        ,$(#[$meta5:meta])*
        $key5:ident: $value5:expr
        ,$(#[$meta6:meta])*
        $key6:ident: $value6:expr
        ,$(#[$meta7:meta])*
        $key7:ident: $value7:expr
        ,$(#[$meta8:meta])*
        $key8:ident: $value8:expr
        ,$(#[$meta9:meta])*
        $key9:ident: $value9:expr
        ,$(#[$meta10:meta])*
        $key10:ident: $value10:expr
        ,$(#[$meta11:meta])*
        $key11:ident: $value11:expr
        ,$(#[$meta12:meta])*
        $key12:ident: $value12:expr
        ,$(#[$meta13:meta])*
        $key13:ident: $value13:expr
        ,$(#[$meta14:meta])*
        $key14:ident: $value14:expr
        ,$(#[$meta15:meta])*
        $key15:ident: $value15:expr
        ,$(#[$meta16:meta])*
        $key16:ident: $value16:expr
        ,$(#[$meta17:meta])*
        $key17:ident: $value17:expr
        ,$(#[$meta18:meta])*
        $key18:ident: $value18:expr
        ,$(#[$meta19:meta])*
        $key19:ident: $value19:expr
        ,$(#[$meta20:meta])*
        $key20:ident: $value20:expr
        ,$(#[$meta21:meta])*
        $key21:ident: $value21:expr
        ,$(#[$meta22:meta])*
        $key22:ident: $value22:expr
        ,$(#[$meta23:meta])*
        $key23:ident: $value23:expr
        $(,)?
    ) => {{
        use $crate::__private::serde;
        #[derive(serde::Serialize)]
        #[allow(non_snake_case)]
            struct Serializable<T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14, T15, T16, T17, T18, T19, T20, T21, T22, T23>{
            $(#[$meta1])*
            $key1: T1,
            $(#[$meta2])*
            $key2: T2,
            $(#[$meta3])*
            $key3: T3,
            $(#[$meta4])*
            $key4: T4,
            $(#[$meta5])*
            $key5: T5,
            $(#[$meta6])*
            $key6: T6,
            $(#[$meta7])*
            $key7: T7,
            $(#[$meta8])*
            $key8: T8,
            $(#[$meta9])*
            $key9: T9,
            $(#[$meta10])*
            $key10: T10,
            $(#[$meta11])*
            $key11: T11,
            $(#[$meta12])*
            $key12: T12,
            $(#[$meta13])*
            $key13: T13,
            $(#[$meta14])*
            $key14: T14,
            $(#[$meta15])*
            $key15: T15,
            $(#[$meta16])*
            $key16: T16,
            $(#[$meta17])*
            $key17: T17,
            $(#[$meta18])*
            $key18: T18,
            $(#[$meta19])*
            $key19: T19,
            $(#[$meta20])*
            $key20: T20,
            $(#[$meta21])*
            $key21: T21,
            $(#[$meta22])*
            $key22: T22,
            $(#[$meta23])*
            $key23: T23,
        }
        Serializable {
            $key1: $value1,
            $key2: $value2,
            $key3: $value3,
            $key4: $value4,
            $key5: $value5,
            $key6: $value6,
            $key7: $value7,
            $key8: $value8,
            $key9: $value9,
            $key10: $value10,
            $key11: $value11,
            $key12: $value12,
            $key13: $value13,
            $key14: $value14,
            $key15: $value15,
            $key16: $value16,
            $key17: $value17,
            $key18: $value18,
            $key19: $value19,
            $key20: $value20,
            $key21: $value21,
            $key22: $value22,
            $key23: $value23,
        }
    }};

    (
        $(#[$meta1:meta])*
        $key1:ident: $value1:expr
        ,$(#[$meta2:meta])*
        $key2:ident: $value2:expr
        ,$(#[$meta3:meta])*
        $key3:ident: $value3:expr
        ,$(#[$meta4:meta])*
        $key4:ident: $value4:expr
        ,$(#[$meta5:meta])*
        $key5:ident: $value5:expr
        ,$(#[$meta6:meta])*
        $key6:ident: $value6:expr
        ,$(#[$meta7:meta])*
        $key7:ident: $value7:expr
        ,$(#[$meta8:meta])*
        $key8:ident: $value8:expr
        ,$(#[$meta9:meta])*
        $key9:ident: $value9:expr
        ,$(#[$meta10:meta])*
        $key10:ident: $value10:expr
        ,$(#[$meta11:meta])*
        $key11:ident: $value11:expr
        ,$(#[$meta12:meta])*
        $key12:ident: $value12:expr
        ,$(#[$meta13:meta])*
        $key13:ident: $value13:expr
        ,$(#[$meta14:meta])*
        $key14:ident: $value14:expr
        ,$(#[$meta15:meta])*
        $key15:ident: $value15:expr
        ,$(#[$meta16:meta])*
        $key16:ident: $value16:expr
        ,$(#[$meta17:meta])*
        $key17:ident: $value17:expr
        ,$(#[$meta18:meta])*
        $key18:ident: $value18:expr
        ,$(#[$meta19:meta])*
        $key19:ident: $value19:expr
        ,$(#[$meta20:meta])*
        $key20:ident: $value20:expr
        ,$(#[$meta21:meta])*
        $key21:ident: $value21:expr
        ,$(#[$meta22:meta])*
        $key22:ident: $value22:expr
        ,$(#[$meta23:meta])*
        $key23:ident: $value23:expr
        ,$(#[$meta24:meta])*
        $key24:ident: $value24:expr
        $(,)?
    ) => {{
        use $crate::__private::serde;
        #[derive(serde::Serialize)]
        #[allow(non_snake_case)]
            struct Serializable<T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14, T15, T16, T17, T18, T19, T20, T21, T22, T23, T24>{
            $(#[$meta1])*
            $key1: T1,
            $(#[$meta2])*
            $key2: T2,
            $(#[$meta3])*
            $key3: T3,
            $(#[$meta4])*
            $key4: T4,
            $(#[$meta5])*
            $key5: T5,
            $(#[$meta6])*
            $key6: T6,
            $(#[$meta7])*
            $key7: T7,
            $(#[$meta8])*
            $key8: T8,
            $(#[$meta9])*
            $key9: T9,
            $(#[$meta10])*
            $key10: T10,
            $(#[$meta11])*
            $key11: T11,
            $(#[$meta12])*
            $key12: T12,
            $(#[$meta13])*
            $key13: T13,
            $(#[$meta14])*
            $key14: T14,
            $(#[$meta15])*
            $key15: T15,
            $(#[$meta16])*
            $key16: T16,
            $(#[$meta17])*
            $key17: T17,
            $(#[$meta18])*
            $key18: T18,
            $(#[$meta19])*
            $key19: T19,
            $(#[$meta20])*
            $key20: T20,
            $(#[$meta21])*
            $key21: T21,
            $(#[$meta22])*
            $key22: T22,
            $(#[$meta23])*
            $key23: T23,
            $(#[$meta24])*
            $key24: T24,
        }
        Serializable {
            $key1: $value1,
            $key2: $value2,
            $key3: $value3,
            $key4: $value4,
            $key5: $value5,
            $key6: $value6,
            $key7: $value7,
            $key8: $value8,
            $key9: $value9,
            $key10: $value10,
            $key11: $value11,
            $key12: $value12,
            $key13: $value13,
            $key14: $value14,
            $key15: $value15,
            $key16: $value16,
            $key17: $value17,
            $key18: $value18,
            $key19: $value19,
            $key20: $value20,
            $key21: $value21,
            $key22: $value22,
            $key23: $value23,
            $key24: $value24,
        }
    }};

    (
        $(#[$meta1:meta])*
        $key1:ident: $value1:expr
        ,$(#[$meta2:meta])*
        $key2:ident: $value2:expr
        ,$(#[$meta3:meta])*
        $key3:ident: $value3:expr
        ,$(#[$meta4:meta])*
        $key4:ident: $value4:expr
        ,$(#[$meta5:meta])*
        $key5:ident: $value5:expr
        ,$(#[$meta6:meta])*
        $key6:ident: $value6:expr
        ,$(#[$meta7:meta])*
        $key7:ident: $value7:expr
        ,$(#[$meta8:meta])*
        $key8:ident: $value8:expr
        ,$(#[$meta9:meta])*
        $key9:ident: $value9:expr
        ,$(#[$meta10:meta])*
        $key10:ident: $value10:expr
        ,$(#[$meta11:meta])*
        $key11:ident: $value11:expr
        ,$(#[$meta12:meta])*
        $key12:ident: $value12:expr
        ,$(#[$meta13:meta])*
        $key13:ident: $value13:expr
        ,$(#[$meta14:meta])*
        $key14:ident: $value14:expr
        ,$(#[$meta15:meta])*
        $key15:ident: $value15:expr
        ,$(#[$meta16:meta])*
        $key16:ident: $value16:expr
        ,$(#[$meta17:meta])*
        $key17:ident: $value17:expr
        ,$(#[$meta18:meta])*
        $key18:ident: $value18:expr
        ,$(#[$meta19:meta])*
        $key19:ident: $value19:expr
        ,$(#[$meta20:meta])*
        $key20:ident: $value20:expr
        ,$(#[$meta21:meta])*
        $key21:ident: $value21:expr
        ,$(#[$meta22:meta])*
        $key22:ident: $value22:expr
        ,$(#[$meta23:meta])*
        $key23:ident: $value23:expr
        ,$(#[$meta24:meta])*
        $key24:ident: $value24:expr
        ,$(#[$meta25:meta])*
        $key25:ident: $value25:expr
        $(,)?
    ) => {{
        use $crate::__private::serde;
        #[derive(serde::Serialize)]
        #[allow(non_snake_case)]
            struct Serializable<T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14, T15, T16, T17, T18, T19, T20, T21, T22, T23, T24, T25>{
            $(#[$meta1])*
            $key1: T1,
            $(#[$meta2])*
            $key2: T2,
            $(#[$meta3])*
            $key3: T3,
            $(#[$meta4])*
            $key4: T4,
            $(#[$meta5])*
            $key5: T5,
            $(#[$meta6])*
            $key6: T6,
            $(#[$meta7])*
            $key7: T7,
            $(#[$meta8])*
            $key8: T8,
            $(#[$meta9])*
            $key9: T9,
            $(#[$meta10])*
            $key10: T10,
            $(#[$meta11])*
            $key11: T11,
            $(#[$meta12])*
            $key12: T12,
            $(#[$meta13])*
            $key13: T13,
            $(#[$meta14])*
            $key14: T14,
            $(#[$meta15])*
            $key15: T15,
            $(#[$meta16])*
            $key16: T16,
            $(#[$meta17])*
            $key17: T17,
            $(#[$meta18])*
            $key18: T18,
            $(#[$meta19])*
            $key19: T19,
            $(#[$meta20])*
            $key20: T20,
            $(#[$meta21])*
            $key21: T21,
            $(#[$meta22])*
            $key22: T22,
            $(#[$meta23])*
            $key23: T23,
            $(#[$meta24])*
            $key24: T24,
            $(#[$meta25])*
            $key25: T25,
        }
        Serializable {
            $key1: $value1,
            $key2: $value2,
            $key3: $value3,
            $key4: $value4,
            $key5: $value5,
            $key6: $value6,
            $key7: $value7,
            $key8: $value8,
            $key9: $value9,
            $key10: $value10,
            $key11: $value11,
            $key12: $value12,
            $key13: $value13,
            $key14: $value14,
            $key15: $value15,
            $key16: $value16,
            $key17: $value17,
            $key18: $value18,
            $key19: $value19,
            $key20: $value20,
            $key21: $value21,
            $key22: $value22,
            $key23: $value23,
            $key24: $value24,
            $key25: $value25,
        }
    }};

    (
        $(#[$meta1:meta])*
        $key1:ident: $value1:expr
        ,$(#[$meta2:meta])*
        $key2:ident: $value2:expr
        ,$(#[$meta3:meta])*
        $key3:ident: $value3:expr
        ,$(#[$meta4:meta])*
        $key4:ident: $value4:expr
        ,$(#[$meta5:meta])*
        $key5:ident: $value5:expr
        ,$(#[$meta6:meta])*
        $key6:ident: $value6:expr
        ,$(#[$meta7:meta])*
        $key7:ident: $value7:expr
        ,$(#[$meta8:meta])*
        $key8:ident: $value8:expr
        ,$(#[$meta9:meta])*
        $key9:ident: $value9:expr
        ,$(#[$meta10:meta])*
        $key10:ident: $value10:expr
        ,$(#[$meta11:meta])*
        $key11:ident: $value11:expr
        ,$(#[$meta12:meta])*
        $key12:ident: $value12:expr
        ,$(#[$meta13:meta])*
        $key13:ident: $value13:expr
        ,$(#[$meta14:meta])*
        $key14:ident: $value14:expr
        ,$(#[$meta15:meta])*
        $key15:ident: $value15:expr
        ,$(#[$meta16:meta])*
        $key16:ident: $value16:expr
        ,$(#[$meta17:meta])*
        $key17:ident: $value17:expr
        ,$(#[$meta18:meta])*
        $key18:ident: $value18:expr
        ,$(#[$meta19:meta])*
        $key19:ident: $value19:expr
        ,$(#[$meta20:meta])*
        $key20:ident: $value20:expr
        ,$(#[$meta21:meta])*
        $key21:ident: $value21:expr
        ,$(#[$meta22:meta])*
        $key22:ident: $value22:expr
        ,$(#[$meta23:meta])*
        $key23:ident: $value23:expr
        ,$(#[$meta24:meta])*
        $key24:ident: $value24:expr
        ,$(#[$meta25:meta])*
        $key25:ident: $value25:expr
        ,$(#[$meta26:meta])*
        $key26:ident: $value26:expr
        $(,)?
    ) => {{
        use $crate::__private::serde;
        #[derive(serde::Serialize)]
        #[allow(non_snake_case)]
            struct Serializable<T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14, T15, T16, T17, T18, T19, T20, T21, T22, T23, T24, T25, T26>{
            $(#[$meta1])*
            $key1: T1,
            $(#[$meta2])*
            $key2: T2,
            $(#[$meta3])*
            $key3: T3,
            $(#[$meta4])*
            $key4: T4,
            $(#[$meta5])*
            $key5: T5,
            $(#[$meta6])*
            $key6: T6,
            $(#[$meta7])*
            $key7: T7,
            $(#[$meta8])*
            $key8: T8,
            $(#[$meta9])*
            $key9: T9,
            $(#[$meta10])*
            $key10: T10,
            $(#[$meta11])*
            $key11: T11,
            $(#[$meta12])*
            $key12: T12,
            $(#[$meta13])*
            $key13: T13,
            $(#[$meta14])*
            $key14: T14,
            $(#[$meta15])*
            $key15: T15,
            $(#[$meta16])*
            $key16: T16,
            $(#[$meta17])*
            $key17: T17,
            $(#[$meta18])*
            $key18: T18,
            $(#[$meta19])*
            $key19: T19,
            $(#[$meta20])*
            $key20: T20,
            $(#[$meta21])*
            $key21: T21,
            $(#[$meta22])*
            $key22: T22,
            $(#[$meta23])*
            $key23: T23,
            $(#[$meta24])*
            $key24: T24,
            $(#[$meta25])*
            $key25: T25,
            $(#[$meta26])*
            $key26: T26,
        }
        Serializable {
            $key1: $value1,
            $key2: $value2,
            $key3: $value3,
            $key4: $value4,
            $key5: $value5,
            $key6: $value6,
            $key7: $value7,
            $key8: $value8,
            $key9: $value9,
            $key10: $value10,
            $key11: $value11,
            $key12: $value12,
            $key13: $value13,
            $key14: $value14,
            $key15: $value15,
            $key16: $value16,
            $key17: $value17,
            $key18: $value18,
            $key19: $value19,
            $key20: $value20,
            $key21: $value21,
            $key22: $value22,
            $key23: $value23,
            $key24: $value24,
            $key25: $value25,
            $key26: $value26,
        }
    }};

    (
        $(#[$meta1:meta])*
        $key1:ident: $value1:expr
        ,$(#[$meta2:meta])*
        $key2:ident: $value2:expr
        ,$(#[$meta3:meta])*
        $key3:ident: $value3:expr
        ,$(#[$meta4:meta])*
        $key4:ident: $value4:expr
        ,$(#[$meta5:meta])*
        $key5:ident: $value5:expr
        ,$(#[$meta6:meta])*
        $key6:ident: $value6:expr
        ,$(#[$meta7:meta])*
        $key7:ident: $value7:expr
        ,$(#[$meta8:meta])*
        $key8:ident: $value8:expr
        ,$(#[$meta9:meta])*
        $key9:ident: $value9:expr
        ,$(#[$meta10:meta])*
        $key10:ident: $value10:expr
        ,$(#[$meta11:meta])*
        $key11:ident: $value11:expr
        ,$(#[$meta12:meta])*
        $key12:ident: $value12:expr
        ,$(#[$meta13:meta])*
        $key13:ident: $value13:expr
        ,$(#[$meta14:meta])*
        $key14:ident: $value14:expr
        ,$(#[$meta15:meta])*
        $key15:ident: $value15:expr
        ,$(#[$meta16:meta])*
        $key16:ident: $value16:expr
        ,$(#[$meta17:meta])*
        $key17:ident: $value17:expr
        ,$(#[$meta18:meta])*
        $key18:ident: $value18:expr
        ,$(#[$meta19:meta])*
        $key19:ident: $value19:expr
        ,$(#[$meta20:meta])*
        $key20:ident: $value20:expr
        ,$(#[$meta21:meta])*
        $key21:ident: $value21:expr
        ,$(#[$meta22:meta])*
        $key22:ident: $value22:expr
        ,$(#[$meta23:meta])*
        $key23:ident: $value23:expr
        ,$(#[$meta24:meta])*
        $key24:ident: $value24:expr
        ,$(#[$meta25:meta])*
        $key25:ident: $value25:expr
        ,$(#[$meta26:meta])*
        $key26:ident: $value26:expr
        ,$(#[$meta27:meta])*
        $key27:ident: $value27:expr
        $(,)?
    ) => {{
        use $crate::__private::serde;
        #[derive(serde::Serialize)]
        #[allow(non_snake_case)]
            struct Serializable<T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14, T15, T16, T17, T18, T19, T20, T21, T22, T23, T24, T25, T26, T27>{
            $(#[$meta1])*
            $key1: T1,
            $(#[$meta2])*
            $key2: T2,
            $(#[$meta3])*
            $key3: T3,
            $(#[$meta4])*
            $key4: T4,
            $(#[$meta5])*
            $key5: T5,
            $(#[$meta6])*
            $key6: T6,
            $(#[$meta7])*
            $key7: T7,
            $(#[$meta8])*
            $key8: T8,
            $(#[$meta9])*
            $key9: T9,
            $(#[$meta10])*
            $key10: T10,
            $(#[$meta11])*
            $key11: T11,
            $(#[$meta12])*
            $key12: T12,
            $(#[$meta13])*
            $key13: T13,
            $(#[$meta14])*
            $key14: T14,
            $(#[$meta15])*
            $key15: T15,
            $(#[$meta16])*
            $key16: T16,
            $(#[$meta17])*
            $key17: T17,
            $(#[$meta18])*
            $key18: T18,
            $(#[$meta19])*
            $key19: T19,
            $(#[$meta20])*
            $key20: T20,
            $(#[$meta21])*
            $key21: T21,
            $(#[$meta22])*
            $key22: T22,
            $(#[$meta23])*
            $key23: T23,
            $(#[$meta24])*
            $key24: T24,
            $(#[$meta25])*
            $key25: T25,
            $(#[$meta26])*
            $key26: T26,
            $(#[$meta27])*
            $key27: T27,
        }
        Serializable {
            $key1: $value1,
            $key2: $value2,
            $key3: $value3,
            $key4: $value4,
            $key5: $value5,
            $key6: $value6,
            $key7: $value7,
            $key8: $value8,
            $key9: $value9,
            $key10: $value10,
            $key11: $value11,
            $key12: $value12,
            $key13: $value13,
            $key14: $value14,
            $key15: $value15,
            $key16: $value16,
            $key17: $value17,
            $key18: $value18,
            $key19: $value19,
            $key20: $value20,
            $key21: $value21,
            $key22: $value22,
            $key23: $value23,
            $key24: $value24,
            $key25: $value25,
            $key26: $value26,
            $key27: $value27,
        }
    }};

    (
        $(#[$meta1:meta])*
        $key1:ident: $value1:expr
        ,$(#[$meta2:meta])*
        $key2:ident: $value2:expr
        ,$(#[$meta3:meta])*
        $key3:ident: $value3:expr
        ,$(#[$meta4:meta])*
        $key4:ident: $value4:expr
        ,$(#[$meta5:meta])*
        $key5:ident: $value5:expr
        ,$(#[$meta6:meta])*
        $key6:ident: $value6:expr
        ,$(#[$meta7:meta])*
        $key7:ident: $value7:expr
        ,$(#[$meta8:meta])*
        $key8:ident: $value8:expr
        ,$(#[$meta9:meta])*
        $key9:ident: $value9:expr
        ,$(#[$meta10:meta])*
        $key10:ident: $value10:expr
        ,$(#[$meta11:meta])*
        $key11:ident: $value11:expr
        ,$(#[$meta12:meta])*
        $key12:ident: $value12:expr
        ,$(#[$meta13:meta])*
        $key13:ident: $value13:expr
        ,$(#[$meta14:meta])*
        $key14:ident: $value14:expr
        ,$(#[$meta15:meta])*
        $key15:ident: $value15:expr
        ,$(#[$meta16:meta])*
        $key16:ident: $value16:expr
        ,$(#[$meta17:meta])*
        $key17:ident: $value17:expr
        ,$(#[$meta18:meta])*
        $key18:ident: $value18:expr
        ,$(#[$meta19:meta])*
        $key19:ident: $value19:expr
        ,$(#[$meta20:meta])*
        $key20:ident: $value20:expr
        ,$(#[$meta21:meta])*
        $key21:ident: $value21:expr
        ,$(#[$meta22:meta])*
        $key22:ident: $value22:expr
        ,$(#[$meta23:meta])*
        $key23:ident: $value23:expr
        ,$(#[$meta24:meta])*
        $key24:ident: $value24:expr
        ,$(#[$meta25:meta])*
        $key25:ident: $value25:expr
        ,$(#[$meta26:meta])*
        $key26:ident: $value26:expr
        ,$(#[$meta27:meta])*
        $key27:ident: $value27:expr
        ,$(#[$meta28:meta])*
        $key28:ident: $value28:expr
        $(,)?
    ) => {{
        use $crate::__private::serde;
        #[derive(serde::Serialize)]
        #[allow(non_snake_case)]
            struct Serializable<T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14, T15, T16, T17, T18, T19, T20, T21, T22, T23, T24, T25, T26, T27, T28>{
            $(#[$meta1])*
            $key1: T1,
            $(#[$meta2])*
            $key2: T2,
            $(#[$meta3])*
            $key3: T3,
            $(#[$meta4])*
            $key4: T4,
            $(#[$meta5])*
            $key5: T5,
            $(#[$meta6])*
            $key6: T6,
            $(#[$meta7])*
            $key7: T7,
            $(#[$meta8])*
            $key8: T8,
            $(#[$meta9])*
            $key9: T9,
            $(#[$meta10])*
            $key10: T10,
            $(#[$meta11])*
            $key11: T11,
            $(#[$meta12])*
            $key12: T12,
            $(#[$meta13])*
            $key13: T13,
            $(#[$meta14])*
            $key14: T14,
            $(#[$meta15])*
            $key15: T15,
            $(#[$meta16])*
            $key16: T16,
            $(#[$meta17])*
            $key17: T17,
            $(#[$meta18])*
            $key18: T18,
            $(#[$meta19])*
            $key19: T19,
            $(#[$meta20])*
            $key20: T20,
            $(#[$meta21])*
            $key21: T21,
            $(#[$meta22])*
            $key22: T22,
            $(#[$meta23])*
            $key23: T23,
            $(#[$meta24])*
            $key24: T24,
            $(#[$meta25])*
            $key25: T25,
            $(#[$meta26])*
            $key26: T26,
            $(#[$meta27])*
            $key27: T27,
            $(#[$meta28])*
            $key28: T28,
        }
        Serializable {
            $key1: $value1,
            $key2: $value2,
            $key3: $value3,
            $key4: $value4,
            $key5: $value5,
            $key6: $value6,
            $key7: $value7,
            $key8: $value8,
            $key9: $value9,
            $key10: $value10,
            $key11: $value11,
            $key12: $value12,
            $key13: $value13,
            $key14: $value14,
            $key15: $value15,
            $key16: $value16,
            $key17: $value17,
            $key18: $value18,
            $key19: $value19,
            $key20: $value20,
            $key21: $value21,
            $key22: $value22,
            $key23: $value23,
            $key24: $value24,
            $key25: $value25,
            $key26: $value26,
            $key27: $value27,
            $key28: $value28,
        }
    }};

    (
        $(#[$meta1:meta])*
        $key1:ident: $value1:expr
        ,$(#[$meta2:meta])*
        $key2:ident: $value2:expr
        ,$(#[$meta3:meta])*
        $key3:ident: $value3:expr
        ,$(#[$meta4:meta])*
        $key4:ident: $value4:expr
        ,$(#[$meta5:meta])*
        $key5:ident: $value5:expr
        ,$(#[$meta6:meta])*
        $key6:ident: $value6:expr
        ,$(#[$meta7:meta])*
        $key7:ident: $value7:expr
        ,$(#[$meta8:meta])*
        $key8:ident: $value8:expr
        ,$(#[$meta9:meta])*
        $key9:ident: $value9:expr
        ,$(#[$meta10:meta])*
        $key10:ident: $value10:expr
        ,$(#[$meta11:meta])*
        $key11:ident: $value11:expr
        ,$(#[$meta12:meta])*
        $key12:ident: $value12:expr
        ,$(#[$meta13:meta])*
        $key13:ident: $value13:expr
        ,$(#[$meta14:meta])*
        $key14:ident: $value14:expr
        ,$(#[$meta15:meta])*
        $key15:ident: $value15:expr
        ,$(#[$meta16:meta])*
        $key16:ident: $value16:expr
        ,$(#[$meta17:meta])*
        $key17:ident: $value17:expr
        ,$(#[$meta18:meta])*
        $key18:ident: $value18:expr
        ,$(#[$meta19:meta])*
        $key19:ident: $value19:expr
        ,$(#[$meta20:meta])*
        $key20:ident: $value20:expr
        ,$(#[$meta21:meta])*
        $key21:ident: $value21:expr
        ,$(#[$meta22:meta])*
        $key22:ident: $value22:expr
        ,$(#[$meta23:meta])*
        $key23:ident: $value23:expr
        ,$(#[$meta24:meta])*
        $key24:ident: $value24:expr
        ,$(#[$meta25:meta])*
        $key25:ident: $value25:expr
        ,$(#[$meta26:meta])*
        $key26:ident: $value26:expr
        ,$(#[$meta27:meta])*
        $key27:ident: $value27:expr
        ,$(#[$meta28:meta])*
        $key28:ident: $value28:expr
        ,$(#[$meta29:meta])*
        $key29:ident: $value29:expr
        $(,)?
    ) => {{
        use $crate::__private::serde;
        #[derive(serde::Serialize)]
        #[allow(non_snake_case)]
            struct Serializable<T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14, T15, T16, T17, T18, T19, T20, T21, T22, T23, T24, T25, T26, T27, T28, T29>{
            $(#[$meta1])*
            $key1: T1,
            $(#[$meta2])*
            $key2: T2,
            $(#[$meta3])*
            $key3: T3,
            $(#[$meta4])*
            $key4: T4,
            $(#[$meta5])*
            $key5: T5,
            $(#[$meta6])*
            $key6: T6,
            $(#[$meta7])*
            $key7: T7,
            $(#[$meta8])*
            $key8: T8,
            $(#[$meta9])*
            $key9: T9,
            $(#[$meta10])*
            $key10: T10,
            $(#[$meta11])*
            $key11: T11,
            $(#[$meta12])*
            $key12: T12,
            $(#[$meta13])*
            $key13: T13,
            $(#[$meta14])*
            $key14: T14,
            $(#[$meta15])*
            $key15: T15,
            $(#[$meta16])*
            $key16: T16,
            $(#[$meta17])*
            $key17: T17,
            $(#[$meta18])*
            $key18: T18,
            $(#[$meta19])*
            $key19: T19,
            $(#[$meta20])*
            $key20: T20,
            $(#[$meta21])*
            $key21: T21,
            $(#[$meta22])*
            $key22: T22,
            $(#[$meta23])*
            $key23: T23,
            $(#[$meta24])*
            $key24: T24,
            $(#[$meta25])*
            $key25: T25,
            $(#[$meta26])*
            $key26: T26,
            $(#[$meta27])*
            $key27: T27,
            $(#[$meta28])*
            $key28: T28,
            $(#[$meta29])*
            $key29: T29,
        }
        Serializable {
            $key1: $value1,
            $key2: $value2,
            $key3: $value3,
            $key4: $value4,
            $key5: $value5,
            $key6: $value6,
            $key7: $value7,
            $key8: $value8,
            $key9: $value9,
            $key10: $value10,
            $key11: $value11,
            $key12: $value12,
            $key13: $value13,
            $key14: $value14,
            $key15: $value15,
            $key16: $value16,
            $key17: $value17,
            $key18: $value18,
            $key19: $value19,
            $key20: $value20,
            $key21: $value21,
            $key22: $value22,
            $key23: $value23,
            $key24: $value24,
            $key25: $value25,
            $key26: $value26,
            $key27: $value27,
            $key28: $value28,
            $key29: $value29,
        }
    }};

    (
        $(#[$meta1:meta])*
        $key1:ident: $value1:expr
        ,$(#[$meta2:meta])*
        $key2:ident: $value2:expr
        ,$(#[$meta3:meta])*
        $key3:ident: $value3:expr
        ,$(#[$meta4:meta])*
        $key4:ident: $value4:expr
        ,$(#[$meta5:meta])*
        $key5:ident: $value5:expr
        ,$(#[$meta6:meta])*
        $key6:ident: $value6:expr
        ,$(#[$meta7:meta])*
        $key7:ident: $value7:expr
        ,$(#[$meta8:meta])*
        $key8:ident: $value8:expr
        ,$(#[$meta9:meta])*
        $key9:ident: $value9:expr
        ,$(#[$meta10:meta])*
        $key10:ident: $value10:expr
        ,$(#[$meta11:meta])*
        $key11:ident: $value11:expr
        ,$(#[$meta12:meta])*
        $key12:ident: $value12:expr
        ,$(#[$meta13:meta])*
        $key13:ident: $value13:expr
        ,$(#[$meta14:meta])*
        $key14:ident: $value14:expr
        ,$(#[$meta15:meta])*
        $key15:ident: $value15:expr
        ,$(#[$meta16:meta])*
        $key16:ident: $value16:expr
        ,$(#[$meta17:meta])*
        $key17:ident: $value17:expr
        ,$(#[$meta18:meta])*
        $key18:ident: $value18:expr
        ,$(#[$meta19:meta])*
        $key19:ident: $value19:expr
        ,$(#[$meta20:meta])*
        $key20:ident: $value20:expr
        ,$(#[$meta21:meta])*
        $key21:ident: $value21:expr
        ,$(#[$meta22:meta])*
        $key22:ident: $value22:expr
        ,$(#[$meta23:meta])*
        $key23:ident: $value23:expr
        ,$(#[$meta24:meta])*
        $key24:ident: $value24:expr
        ,$(#[$meta25:meta])*
        $key25:ident: $value25:expr
        ,$(#[$meta26:meta])*
        $key26:ident: $value26:expr
        ,$(#[$meta27:meta])*
        $key27:ident: $value27:expr
        ,$(#[$meta28:meta])*
        $key28:ident: $value28:expr
        ,$(#[$meta29:meta])*
        $key29:ident: $value29:expr
        ,$(#[$meta30:meta])*
        $key30:ident: $value30:expr
        $(,)?
    ) => {{
        use $crate::__private::serde;
        #[derive(serde::Serialize)]
        #[allow(non_snake_case)]
            struct Serializable<T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14, T15, T16, T17, T18, T19, T20, T21, T22, T23, T24, T25, T26, T27, T28, T29, T30>{
            $(#[$meta1])*
            $key1: T1,
            $(#[$meta2])*
            $key2: T2,
            $(#[$meta3])*
            $key3: T3,
            $(#[$meta4])*
            $key4: T4,
            $(#[$meta5])*
            $key5: T5,
            $(#[$meta6])*
            $key6: T6,
            $(#[$meta7])*
            $key7: T7,
            $(#[$meta8])*
            $key8: T8,
            $(#[$meta9])*
            $key9: T9,
            $(#[$meta10])*
            $key10: T10,
            $(#[$meta11])*
            $key11: T11,
            $(#[$meta12])*
            $key12: T12,
            $(#[$meta13])*
            $key13: T13,
            $(#[$meta14])*
            $key14: T14,
            $(#[$meta15])*
            $key15: T15,
            $(#[$meta16])*
            $key16: T16,
            $(#[$meta17])*
            $key17: T17,
            $(#[$meta18])*
            $key18: T18,
            $(#[$meta19])*
            $key19: T19,
            $(#[$meta20])*
            $key20: T20,
            $(#[$meta21])*
            $key21: T21,
            $(#[$meta22])*
            $key22: T22,
            $(#[$meta23])*
            $key23: T23,
            $(#[$meta24])*
            $key24: T24,
            $(#[$meta25])*
            $key25: T25,
            $(#[$meta26])*
            $key26: T26,
            $(#[$meta27])*
            $key27: T27,
            $(#[$meta28])*
            $key28: T28,
            $(#[$meta29])*
            $key29: T29,
            $(#[$meta30])*
            $key30: T30,
        }
        Serializable {
            $key1: $value1,
            $key2: $value2,
            $key3: $value3,
            $key4: $value4,
            $key5: $value5,
            $key6: $value6,
            $key7: $value7,
            $key8: $value8,
            $key9: $value9,
            $key10: $value10,
            $key11: $value11,
            $key12: $value12,
            $key13: $value13,
            $key14: $value14,
            $key15: $value15,
            $key16: $value16,
            $key17: $value17,
            $key18: $value18,
            $key19: $value19,
            $key20: $value20,
            $key21: $value21,
            $key22: $value22,
            $key23: $value23,
            $key24: $value24,
            $key25: $value25,
            $key26: $value26,
            $key27: $value27,
            $key28: $value28,
            $key29: $value29,
            $key30: $value30,
        }
    }};

    (
        $(#[$meta1:meta])*
        $key1:ident: $value1:expr
        ,$(#[$meta2:meta])*
        $key2:ident: $value2:expr
        ,$(#[$meta3:meta])*
        $key3:ident: $value3:expr
        ,$(#[$meta4:meta])*
        $key4:ident: $value4:expr
        ,$(#[$meta5:meta])*
        $key5:ident: $value5:expr
        ,$(#[$meta6:meta])*
        $key6:ident: $value6:expr
        ,$(#[$meta7:meta])*
        $key7:ident: $value7:expr
        ,$(#[$meta8:meta])*
        $key8:ident: $value8:expr
        ,$(#[$meta9:meta])*
        $key9:ident: $value9:expr
        ,$(#[$meta10:meta])*
        $key10:ident: $value10:expr
        ,$(#[$meta11:meta])*
        $key11:ident: $value11:expr
        ,$(#[$meta12:meta])*
        $key12:ident: $value12:expr
        ,$(#[$meta13:meta])*
        $key13:ident: $value13:expr
        ,$(#[$meta14:meta])*
        $key14:ident: $value14:expr
        ,$(#[$meta15:meta])*
        $key15:ident: $value15:expr
        ,$(#[$meta16:meta])*
        $key16:ident: $value16:expr
        ,$(#[$meta17:meta])*
        $key17:ident: $value17:expr
        ,$(#[$meta18:meta])*
        $key18:ident: $value18:expr
        ,$(#[$meta19:meta])*
        $key19:ident: $value19:expr
        ,$(#[$meta20:meta])*
        $key20:ident: $value20:expr
        ,$(#[$meta21:meta])*
        $key21:ident: $value21:expr
        ,$(#[$meta22:meta])*
        $key22:ident: $value22:expr
        ,$(#[$meta23:meta])*
        $key23:ident: $value23:expr
        ,$(#[$meta24:meta])*
        $key24:ident: $value24:expr
        ,$(#[$meta25:meta])*
        $key25:ident: $value25:expr
        ,$(#[$meta26:meta])*
        $key26:ident: $value26:expr
        ,$(#[$meta27:meta])*
        $key27:ident: $value27:expr
        ,$(#[$meta28:meta])*
        $key28:ident: $value28:expr
        ,$(#[$meta29:meta])*
        $key29:ident: $value29:expr
        ,$(#[$meta30:meta])*
        $key30:ident: $value30:expr
        ,$(#[$meta31:meta])*
        $key31:ident: $value31:expr
        $(,)?
    ) => {{
        use $crate::__private::serde;
        #[derive(serde::Serialize)]
        #[allow(non_snake_case)]
            struct Serializable<T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14, T15, T16, T17, T18, T19, T20, T21, T22, T23, T24, T25, T26, T27, T28, T29, T30, T31>{
            $(#[$meta1])*
            $key1: T1,
            $(#[$meta2])*
            $key2: T2,
            $(#[$meta3])*
            $key3: T3,
            $(#[$meta4])*
            $key4: T4,
            $(#[$meta5])*
            $key5: T5,
            $(#[$meta6])*
            $key6: T6,
            $(#[$meta7])*
            $key7: T7,
            $(#[$meta8])*
            $key8: T8,
            $(#[$meta9])*
            $key9: T9,
            $(#[$meta10])*
            $key10: T10,
            $(#[$meta11])*
            $key11: T11,
            $(#[$meta12])*
            $key12: T12,
            $(#[$meta13])*
            $key13: T13,
            $(#[$meta14])*
            $key14: T14,
            $(#[$meta15])*
            $key15: T15,
            $(#[$meta16])*
            $key16: T16,
            $(#[$meta17])*
            $key17: T17,
            $(#[$meta18])*
            $key18: T18,
            $(#[$meta19])*
            $key19: T19,
            $(#[$meta20])*
            $key20: T20,
            $(#[$meta21])*
            $key21: T21,
            $(#[$meta22])*
            $key22: T22,
            $(#[$meta23])*
            $key23: T23,
            $(#[$meta24])*
            $key24: T24,
            $(#[$meta25])*
            $key25: T25,
            $(#[$meta26])*
            $key26: T26,
            $(#[$meta27])*
            $key27: T27,
            $(#[$meta28])*
            $key28: T28,
            $(#[$meta29])*
            $key29: T29,
            $(#[$meta30])*
            $key30: T30,
            $(#[$meta31])*
            $key31: T31,
        }
        Serializable {
            $key1: $value1,
            $key2: $value2,
            $key3: $value3,
            $key4: $value4,
            $key5: $value5,
            $key6: $value6,
            $key7: $value7,
            $key8: $value8,
            $key9: $value9,
            $key10: $value10,
            $key11: $value11,
            $key12: $value12,
            $key13: $value13,
            $key14: $value14,
            $key15: $value15,
            $key16: $value16,
            $key17: $value17,
            $key18: $value18,
            $key19: $value19,
            $key20: $value20,
            $key21: $value21,
            $key22: $value22,
            $key23: $value23,
            $key24: $value24,
            $key25: $value25,
            $key26: $value26,
            $key27: $value27,
            $key28: $value28,
            $key29: $value29,
            $key30: $value30,
            $key31: $value31,
        }
    }};

    (
        $(#[$meta1:meta])*
        $key1:ident: $value1:expr
        ,$(#[$meta2:meta])*
        $key2:ident: $value2:expr
        ,$(#[$meta3:meta])*
        $key3:ident: $value3:expr
        ,$(#[$meta4:meta])*
        $key4:ident: $value4:expr
        ,$(#[$meta5:meta])*
        $key5:ident: $value5:expr
        ,$(#[$meta6:meta])*
        $key6:ident: $value6:expr
        ,$(#[$meta7:meta])*
        $key7:ident: $value7:expr
        ,$(#[$meta8:meta])*
        $key8:ident: $value8:expr
        ,$(#[$meta9:meta])*
        $key9:ident: $value9:expr
        ,$(#[$meta10:meta])*
        $key10:ident: $value10:expr
        ,$(#[$meta11:meta])*
        $key11:ident: $value11:expr
        ,$(#[$meta12:meta])*
        $key12:ident: $value12:expr
        ,$(#[$meta13:meta])*
        $key13:ident: $value13:expr
        ,$(#[$meta14:meta])*
        $key14:ident: $value14:expr
        ,$(#[$meta15:meta])*
        $key15:ident: $value15:expr
        ,$(#[$meta16:meta])*
        $key16:ident: $value16:expr
        ,$(#[$meta17:meta])*
        $key17:ident: $value17:expr
        ,$(#[$meta18:meta])*
        $key18:ident: $value18:expr
        ,$(#[$meta19:meta])*
        $key19:ident: $value19:expr
        ,$(#[$meta20:meta])*
        $key20:ident: $value20:expr
        ,$(#[$meta21:meta])*
        $key21:ident: $value21:expr
        ,$(#[$meta22:meta])*
        $key22:ident: $value22:expr
        ,$(#[$meta23:meta])*
        $key23:ident: $value23:expr
        ,$(#[$meta24:meta])*
        $key24:ident: $value24:expr
        ,$(#[$meta25:meta])*
        $key25:ident: $value25:expr
        ,$(#[$meta26:meta])*
        $key26:ident: $value26:expr
        ,$(#[$meta27:meta])*
        $key27:ident: $value27:expr
        ,$(#[$meta28:meta])*
        $key28:ident: $value28:expr
        ,$(#[$meta29:meta])*
        $key29:ident: $value29:expr
        ,$(#[$meta30:meta])*
        $key30:ident: $value30:expr
        ,$(#[$meta31:meta])*
        $key31:ident: $value31:expr
        ,$(#[$meta32:meta])*
        $key32:ident: $value32:expr
        $(,)?
    ) => {{
        use $crate::__private::serde;
        #[derive(serde::Serialize)]
        #[allow(non_snake_case)]
            struct Serializable<T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14, T15, T16, T17, T18, T19, T20, T21, T22, T23, T24, T25, T26, T27, T28, T29, T30, T31, T32>{
            $(#[$meta1])*
            $key1: T1,
            $(#[$meta2])*
            $key2: T2,
            $(#[$meta3])*
            $key3: T3,
            $(#[$meta4])*
            $key4: T4,
            $(#[$meta5])*
            $key5: T5,
            $(#[$meta6])*
            $key6: T6,
            $(#[$meta7])*
            $key7: T7,
            $(#[$meta8])*
            $key8: T8,
            $(#[$meta9])*
            $key9: T9,
            $(#[$meta10])*
            $key10: T10,
            $(#[$meta11])*
            $key11: T11,
            $(#[$meta12])*
            $key12: T12,
            $(#[$meta13])*
            $key13: T13,
            $(#[$meta14])*
            $key14: T14,
            $(#[$meta15])*
            $key15: T15,
            $(#[$meta16])*
            $key16: T16,
            $(#[$meta17])*
            $key17: T17,
            $(#[$meta18])*
            $key18: T18,
            $(#[$meta19])*
            $key19: T19,
            $(#[$meta20])*
            $key20: T20,
            $(#[$meta21])*
            $key21: T21,
            $(#[$meta22])*
            $key22: T22,
            $(#[$meta23])*
            $key23: T23,
            $(#[$meta24])*
            $key24: T24,
            $(#[$meta25])*
            $key25: T25,
            $(#[$meta26])*
            $key26: T26,
            $(#[$meta27])*
            $key27: T27,
            $(#[$meta28])*
            $key28: T28,
            $(#[$meta29])*
            $key29: T29,
            $(#[$meta30])*
            $key30: T30,
            $(#[$meta31])*
            $key31: T31,
            $(#[$meta32])*
            $key32: T32,
        }
        Serializable {
            $key1: $value1,
            $key2: $value2,
            $key3: $value3,
            $key4: $value4,
            $key5: $value5,
            $key6: $value6,
            $key7: $value7,
            $key8: $value8,
            $key9: $value9,
            $key10: $value10,
            $key11: $value11,
            $key12: $value12,
            $key13: $value13,
            $key14: $value14,
            $key15: $value15,
            $key16: $value16,
            $key17: $value17,
            $key18: $value18,
            $key19: $value19,
            $key20: $value20,
            $key21: $value21,
            $key22: $value22,
            $key23: $value23,
            $key24: $value24,
            $key25: $value25,
            $key26: $value26,
            $key27: $value27,
            $key28: $value28,
            $key29: $value29,
            $key30: $value30,
            $key31: $value31,
            $key32: $value32,
        }
    }};
}
