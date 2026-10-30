/**
 * @file tests/unit/test_display_selection.cpp
 * @brief Tests requested-display validation and default fallback.
 */

// test includes
#include "../tests_common.h"

// standard includes
#include <string>
#include <vector>

// local includes
#include <src/video.h>

TEST(DisplaySelectionTest, KeepsAnAvailableStableId) {
  const std::vector<video::display_info_t> displays {
    {"\\\\?\\DISPLAY#A1", "Desk monitor"},
    {"\\\\?\\DISPLAY#B2", "Side monitor"},
  };

  EXPECT_EQ(video::validate_display_id("\\\\?\\DISPLAY#B2", displays), "\\\\?\\DISPLAY#B2");
}

TEST(DisplaySelectionTest, MissingOrUnsupportedIdsFallBackToConfiguredDefault) {
  const std::vector<video::display_info_t> displays {
    {"\\\\?\\DISPLAY#A1", "Desk monitor"},
  };

  EXPECT_TRUE(video::validate_display_id("\\\\?\\DISPLAY#removed", displays).empty());
  EXPECT_TRUE(video::validate_display_id("", displays).empty());
  EXPECT_EQ(video::validate_display_id("\\\\?\\DISPLAY#A1", displays), "\\\\?\\DISPLAY#A1");
  EXPECT_TRUE(video::validate_display_id("\\\\?\\DISPLAY#A1", {}).empty());
}
