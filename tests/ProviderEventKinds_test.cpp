#include <gtest/gtest.h>
#include "collector/ProviderEventKinds.h"

using angelia::collector::EventKind;
using angelia::collector::kernel_file_kind_from_id;

TEST(KernelFileEventKinds, MapsInstalledManifestIds) {
    EXPECT_EQ(kernel_file_kind_from_id(12), EventKind::FileOpen);
    EXPECT_EQ(kernel_file_kind_from_id(14), EventKind::FileClose);
    EXPECT_EQ(kernel_file_kind_from_id(15), EventKind::FileRead);
    EXPECT_EQ(kernel_file_kind_from_id(16), EventKind::FileWrite);
    EXPECT_EQ(kernel_file_kind_from_id(19), EventKind::FileRename);
    EXPECT_EQ(kernel_file_kind_from_id(24), EventKind::FileOperationEnd);
    EXPECT_EQ(kernel_file_kind_from_id(30), EventKind::FileCreate);
    EXPECT_EQ(kernel_file_kind_from_id(99), EventKind::Unknown);
}
