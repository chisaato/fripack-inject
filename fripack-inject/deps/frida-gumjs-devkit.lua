package("frida-gumjs-devkit")
    on_install(function (package)
        local dir = package:scriptdir() .. "/frida-gumjs-devkit"
        io.replace(dir .. "/gumenumtypes.h", "#include <glib-object.h>", "// #include <glib-object.h>", {plain = true})
        os.cp(dir .. "/frida-gumjs.h", package:installdir("include"))
        os.cp(dir .. "/gumenumtypes.h", package:installdir("include", "gum"))
        os.cp(dir .. "/*.a", package:installdir("lib"))
        os.cp(dir .. "/*.lib", package:installdir("lib"))
    end)

    add_links("frida-gumjs")