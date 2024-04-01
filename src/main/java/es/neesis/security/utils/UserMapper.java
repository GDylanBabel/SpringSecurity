package es.neesis.security.utils;

import es.neesis.security.model.User;
import es.neesis.security.model.dto.UserDTO;
import lombok.NoArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Component;

@Component
@NoArgsConstructor
public class UserMapper {

    private static final ModelMapper modelMapper = new ModelMapper();

    public static UserDTO convertToDto(User user) {
        return modelMapper.map(user, UserDTO.class);
    }

    public static User convertToEntity(UserDTO userDTO) {
        return modelMapper.map(userDTO, User.class);
    }
}

