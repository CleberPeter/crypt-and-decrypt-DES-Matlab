%Autor: Cleber Peter

%função converte de array binário para uma string hexadecimal
function output_hex = convert_to_hex(in_bin)
    for i=0:((size(in_bin,2)/8) -1)
        output_hex(1,(1:2)+2*i) = dec2hex(bi2de(in_bin(1,(1:8)+8*i),'left-msb'),2);
    end
end